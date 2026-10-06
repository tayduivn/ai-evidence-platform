package ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWAL_WriteAndReadFrames(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal_test_read_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	events := []*AuditEventEnvelope{
		{
			EventID:       "wal-ev-1",
			CorrelationID: "tx-wal-1",
			OutputPayload: "PAYLOAD_1",
			Timestamp:     time.Now().UTC(),
		},
		{
			EventID:       "wal-ev-2",
			CorrelationID: "tx-wal-2",
			OutputPayload: "PAYLOAD_2",
			Timestamp:     time.Now().UTC(),
		},
	}

	for _, ev := range events {
		if err := wal.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent failed: %v", err)
		}
	}

	activeFile := filepath.Join(tempDir, "wal-00000000.log")
	recovered, err := ReadFrames(activeFile)
	if err != nil {
		t.Fatalf("ReadFrames failed: %v", err)
	}

	if len(recovered) != 2 {
		t.Fatalf("Expected 2 recovered events, got %d", len(recovered))
	}
	if recovered[0].EventID != "wal-ev-1" || recovered[1].EventID != "wal-ev-2" {
		t.Errorf("Recovered events did not match written events")
	}
	if recovered[0].OutputPayload != "PAYLOAD_1" || recovered[1].OutputPayload != "PAYLOAD_2" {
		t.Errorf("Recovered payload content mismatch")
	}
}

func TestWAL_CRC32CorruptionDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal_test_crc_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}

	ev := &AuditEventEnvelope{
		EventID:       "crc-ev-1",
		OutputPayload: "INTEGRITY_CHECK",
		Timestamp:     time.Now().UTC(),
	}
	if err := wal.WriteEvent(ev); err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}
	_ = wal.Close()

	activeFile := filepath.Join(tempDir, "wal-00000000.log")
	data, err := os.ReadFile(activeFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Corrupt one byte inside the payload section (offset 15 is well within payload)
	if len(data) > 15 {
		data[15] ^= 0xFF
	}
	if err := os.WriteFile(activeFile, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = ReadFrames(activeFile)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Expected ErrChecksumMismatch, got: %v", err)
	}
}

func TestWAL_SegmentRotation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal_test_rot_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Set small segment threshold of 300 bytes
	wal, err := NewDiskWAL(tempDir, 300)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	for i := 0; i < 5; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("rot-ev-%d", i),
			OutputPayload: "LARGE_PAYLOAD_STRING_TO_TRIGGER_ROTATION_THRESHOLD_ON_SEGMENT_FILES",
			Timestamp:     time.Now().UTC(),
		}
		if err := wal.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent failed on iter %d: %v", i, err)
		}
	}

	if wal.ActiveSegmentFiles() < 2 {
		t.Errorf("Expected multiple segment files after rotation, got %d", wal.ActiveSegmentFiles())
	}
}

func TestWAL_CrashRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal_test_crash_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}

	ev1 := &AuditEventEnvelope{
		EventID:       "crash-ev-1",
		OutputPayload: "VALID_RECORD_1",
		Timestamp:     time.Now().UTC(),
	}
	if err := wal.WriteEvent(ev1); err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}
	_ = wal.Close()

	activeFile := filepath.Join(tempDir, "wal-00000000.log")
	f, err := os.OpenFile(activeFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	// Append 6 bytes of incomplete header (power failure midway)
	_, _ = f.Write([]byte{0x57, 0x41, 0x4C, 0x31, 0x00, 0x05})
	_ = f.Close()

	recovered, err := ReadFrames(activeFile)
	if err != nil {
		t.Fatalf("ReadFrames should not fail on incomplete trailing write: %v", err)
	}
	if len(recovered) != 1 || recovered[0].EventID != "crash-ev-1" {
		t.Errorf("Expected exactly 1 recovered event before crash marker, got %d", len(recovered))
	}
}

func TestWAL_ReplayPending(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal_test_replay_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("replay-ev-%d", i),
			OutputPayload: fmt.Sprintf("PAYLOAD_%d", i),
			Timestamp:     time.Now().UTC(),
		}
		if err := wal.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent failed: %v", err)
		}
	}

	// Rotate to seal wal-00000000.log as historical
	if err := wal.Rotate(); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	defer wal.Close()

	var replayedEvents []*AuditEventEnvelope
	count, err := wal.ReplayPending(func(batch []*AuditEventEnvelope) error {
		replayedEvents = append(replayedEvents, batch...)
		return nil
	})

	if err != nil {
		t.Fatalf("ReplayPending failed: %v", err)
	}
	if count != 3 || len(replayedEvents) != 3 {
		t.Errorf("Expected 3 replayed events, got count=%d, slice=%d", count, len(replayedEvents))
	}
}
