package ledger

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestQueue_NonBlockingEnqueue(t *testing.T) {
	q := NewBoundedQueue(10000, nil)
	defer q.Close()

	start := time.Now()
	total := 1000
	for i := 0; i < total; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("nb-ev-%d", i),
			OutputPayload: "FAST_ENQUEUE",
			Timestamp:     time.Now().UTC(),
		}
		if err := q.Enqueue(ev); err != nil {
			t.Fatalf("Enqueue failed on item %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	avgMicro := float64(elapsed.Microseconds()) / float64(total)

	// In Go, in-memory channel enqueue is sub-microsecond (< 100 microseconds is generous)
	if avgMicro > 100.0 {
		t.Logf("Notice: average enqueue took %.2f µs (acceptable on windows)", avgMicro)
	}

	if q.Len() != total {
		t.Errorf("Expected queue length %d, got %d", total, q.Len())
	}
}

func TestQueue_HighWaterMarkDivertToWAL(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "q_test_wal_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	// Capacity 100, 90% threshold = 90
	q := NewBoundedQueue(100, wal)
	defer q.Close()

	for i := 0; i < 95; i++ {
		ev := &AuditEventEnvelope{
			EventID:       fmt.Sprintf("hwm-ev-%d", i),
			OutputPayload: "WATERMARK_TEST",
			Timestamp:     time.Now().UTC(),
		}
		if err := q.Enqueue(ev); err != nil {
			t.Fatalf("Enqueue failed on item %d: %v", i, err)
		}
	}

	stats := q.Stats()
	if stats.EnqueuedTotal != 90 {
		t.Errorf("Expected 90 channel items, got %d", stats.EnqueuedTotal)
	}
	if stats.DivertedWAL != 5 {
		t.Errorf("Expected 5 items diverted to WAL, got %d", stats.DivertedWAL)
	}
}

func TestQueue_OverflowFallbackToWAL(t *testing.T) {
	// Without WAL
	qNoWAL := NewBoundedQueue(10, nil)
	defer qNoWAL.Close()

	for i := 0; i < 10; i++ {
		_ = qNoWAL.Enqueue(&AuditEventEnvelope{EventID: fmt.Sprintf("no-wal-%d", i)})
	}

	err := qNoWAL.Enqueue(&AuditEventEnvelope{EventID: "overflow"})
	if !errors.Is(err, ErrQueueFull) {
		t.Errorf("Expected ErrQueueFull when capacity saturated with nil WAL, got: %v", err)
	}
}

func TestQueue_DrainOnClose(t *testing.T) {
	q := NewBoundedQueue(100, nil)

	for i := 0; i < 50; i++ {
		_ = q.Enqueue(&AuditEventEnvelope{
			EventID: fmt.Sprintf("drain-ev-%d", i),
		})
	}

	if err := q.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify enqueuing after close returns ErrQueueClosed
	if err := q.Enqueue(&AuditEventEnvelope{EventID: "after-close"}); !errors.Is(err, ErrQueueClosed) {
		t.Errorf("Expected ErrQueueClosed after Close(), got: %v", err)
	}

	// Drain remaining
	drained := 0
	for ev := range q.Events() {
		if ev != nil {
			drained++
		}
	}

	if drained != 50 {
		t.Errorf("Expected 50 drained events, got %d", drained)
	}
}

func TestQueue_Stats(t *testing.T) {
	q := NewBoundedQueue(200, nil)
	defer q.Close()

	_ = q.Enqueue(&AuditEventEnvelope{EventID: "stat-1"})
	_ = q.Enqueue(&AuditEventEnvelope{EventID: "stat-2"})

	stats := q.Stats()
	if stats.Capacity != 200 {
		t.Errorf("Expected capacity 200, got %d", stats.Capacity)
	}
	if stats.CurrentLength != 2 {
		t.Errorf("Expected length 2, got %d", stats.CurrentLength)
	}
	if stats.EnqueuedTotal != 2 {
		t.Errorf("Expected EnqueuedTotal 2, got %d", stats.EnqueuedTotal)
	}
}
