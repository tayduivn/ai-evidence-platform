package ledger

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	walMagic           uint32 = 0x57414C31 // "WAL1"
	defaultMaxSegBytes int64  = 10 * 1024 * 1024 // 10 MB
)

var (
	ErrChecksumMismatch = errors.New("wal frame crc32 checksum mismatch")
	ErrCorruptFrame     = errors.New("wal frame header corrupt or invalid magic")
	ErrWALClosed        = errors.New("wal is closed")
)

// WALManager defines the interface for local disk fallback logging.
type WALManager interface {
	WriteEvent(event *AuditEventEnvelope) error
	Rotate() error
	Close() error
	ActiveSegmentFiles() int
	ReplayPending(replayer func(batch []*AuditEventEnvelope) error) (int, error)
}

// DiskWAL implements a segmented binary Write-Ahead Log.
type DiskWAL struct {
	dir         string
	maxBytes    int64
	activeFile  *os.File
	activeSeq   uint64
	currentSize int64
	closed      bool
	mu          sync.Mutex
}

// NewDiskWAL creates or opens a segmented DiskWAL in the specified directory.
func NewDiskWAL(dir string, maxBytes int64) (*DiskWAL, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxSegBytes
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create wal directory: %w", err)
	}

	w := &DiskWAL{
		dir:      dir,
		maxBytes: maxBytes,
	}

	// Find the highest sequence number in directory
	seq, err := w.findHighestSeq()
	if err != nil {
		return nil, err
	}

	// CRASH RECOVERY FIX: If the highest sequence file already exists and has uncommitted
	// data (size > 0), seal it as historical by incrementing activeSeq to seq + 1.
	// This ensures that ReplayPending will see seq < activeSeq and replay all
	// pre-crash uncommitted events upon restart, while post-restart events are appended
	// to a clean new segment.
	activePath := filepath.Join(w.dir, fmt.Sprintf("wal-%08d.log", seq))
	if info, err := os.Stat(activePath); err == nil && info.Size() > 0 {
		seq++
	}
	w.activeSeq = seq

	if err := w.openActive(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *DiskWAL) findHighestSeq() (uint64, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0, err
	}

	var maxSeq uint64 = 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "wal-") && strings.HasSuffix(name, ".log") {
			numPart := strings.TrimSuffix(strings.TrimPrefix(name, "wal-"), ".log")
			if seq, parseErr := strconv.ParseUint(numPart, 10, 64); parseErr == nil {
				if seq > maxSeq {
					maxSeq = seq
				}
			}
		}
	}
	return maxSeq, nil
}

func (w *DiskWAL) openActive() error {
	filePath := filepath.Join(w.dir, fmt.Sprintf("wal-%08d.log", w.activeSeq))
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open wal file %s: %w", filePath, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to stat wal file: %w", err)
	}

	w.activeFile = f
	w.currentSize = info.Size()
	return nil
}

// WriteEvent frames and appends an audit event to the active WAL segment.
func (w *DiskWAL) WriteEvent(event *AuditEventEnvelope) error {
	if event == nil {
		return errors.New("event cannot be nil")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWALClosed
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event for wal: %w", err)
	}

	payloadLen := uint32(len(payload))
	checksum := crc32.ChecksumIEEE(payload)

	// Frame structure: Magic(4B) + Length(4B) + CRC32(4B) + Payload(NB)
	frame := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], walMagic)
	binary.BigEndian.PutUint32(frame[4:8], payloadLen)
	binary.BigEndian.PutUint32(frame[8:12], checksum)
	copy(frame[12:], payload)

	n, err := w.activeFile.Write(frame)
	if err != nil {
		return fmt.Errorf("failed to write wal frame: %w", err)
	}
	_ = w.activeFile.Sync()

	w.currentSize += int64(n)
	if w.currentSize >= w.maxBytes {
		return w.rotateLocked()
	}

	return nil
}

func (w *DiskWAL) rotateLocked() error {
	if w.activeFile != nil {
		_ = w.activeFile.Sync()
		_ = w.activeFile.Close()
	}
	w.activeSeq++
	w.currentSize = 0
	return w.openActive()
}

// Rotate closes the current segment and starts a new one.
func (w *DiskWAL) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWALClosed
	}
	return w.rotateLocked()
}

// Close flushes and closes the active WAL segment.
func (w *DiskWAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.activeFile != nil {
		_ = w.activeFile.Sync()
		return w.activeFile.Close()
	}
	return nil
}

// ActiveSegmentFiles returns the number of WAL log files present in the directory.
func (w *DiskWAL) ActiveSegmentFiles() int {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "wal-") && strings.HasSuffix(entry.Name(), ".log") {
			count++
		}
	}
	return count
}

// ReadFrames parses and verifies all framed records in a specific WAL file.
func ReadFrames(filePath string) ([]*AuditEventEnvelope, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []*AuditEventEnvelope
	headerBuf := make([]byte, 12)

	for {
		_, err := io.ReadFull(f, headerBuf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return events, fmt.Errorf("error reading frame header: %w", err)
		}

		magic := binary.BigEndian.PutUint32 // no-op check
		_ = magic
		m := binary.BigEndian.Uint32(headerBuf[0:4])
		if m != walMagic {
			return events, ErrCorruptFrame
		}

		payloadLen := binary.BigEndian.Uint32(headerBuf[4:8])
		expectedChecksum := binary.BigEndian.Uint32(headerBuf[8:12])

		// Reject maliciously large or corrupted frame length headers to avoid OOM
		const maxAllowedPayloadLen = 16 * 1024 * 1024 // 16 MB max frame size
		if payloadLen > maxAllowedPayloadLen {
			return events, ErrCorruptFrame
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			// Incomplete trailing payload during crash
			break
		}

		actualChecksum := crc32.ChecksumIEEE(payload)
		if actualChecksum != expectedChecksum {
			return events, ErrChecksumMismatch
		}

		var event AuditEventEnvelope
		if err := json.Unmarshal(payload, &event); err != nil {
			return events, fmt.Errorf("failed to unmarshal event: %w", err)
		}

		events = append(events, &event)
	}

	return events, nil
}

// ReplayPending scans for historical segments prior to the active one, replays them via callback, and removes them.
func (w *DiskWAL) ReplayPending(replayer func(batch []*AuditEventEnvelope) error) (int, error) {
	w.mu.Lock()
	currentActiveSeq := w.activeSeq
	w.mu.Unlock()

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0, err
	}

	var segmentFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "wal-") && strings.HasSuffix(name, ".log") {
			numPart := strings.TrimSuffix(strings.TrimPrefix(name, "wal-"), ".log")
			if seq, parseErr := strconv.ParseUint(numPart, 10, 64); parseErr == nil {
				// Replay files older than activeSeq, or activeSeq if rotated/draining
				if seq < currentActiveSeq {
					segmentFiles = append(segmentFiles, filepath.Join(w.dir, name))
				}
			}
		}
	}

	sort.Strings(segmentFiles)
	replayedCount := 0

	for _, segPath := range segmentFiles {
		events, err := ReadFrames(segPath)
		if err != nil && !errors.Is(err, ErrChecksumMismatch) {
			return replayedCount, fmt.Errorf("failed reading segment %s: %w", segPath, err)
		}

		if len(events) > 0 {
			if err := replayer(events); err != nil {
				return replayedCount, fmt.Errorf("replayer error on %s: %w", segPath, err)
			}
			replayedCount += len(events)
		}

		// If segment failed due to checksum mismatch, quarantine it for forensic inspection
		if errors.Is(err, ErrChecksumMismatch) {
			_ = os.Rename(segPath, segPath+".corrupt")
		} else {
			_ = os.Remove(segPath)
		}
	}

	return replayedCount, nil
}
