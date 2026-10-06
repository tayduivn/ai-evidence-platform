package ledger

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestWorker_FlushBySize(t *testing.T) {
	q := NewBoundedQueue(1000, nil)
	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	cfg := WorkerConfig{
		BatchSize:         50,
		FlushInterval:     5 * time.Second, // Long interval so size trigger fires first
		WALReplayInterval: 1 * time.Second,
	}

	worker := NewMicroBatchWorker(cfg, q, client, tree, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)
	defer worker.Stop()

	// Enqueue exactly 50 items
	for i := 0; i < 50; i++ {
		_ = q.Enqueue(&AuditEventEnvelope{
			EventID:       fmt.Sprintf("size-ev-%d", i),
			OutputPayload: "BATCH_PAYLOAD",
			Timestamp:     time.Now().UTC(),
		})
	}

	// Wait briefly for size flusher to commit
	time.Sleep(100 * time.Millisecond)

	events, batches, _ := worker.Stats()
	if events != 50 {
		t.Errorf("Expected 50 events ingested, got %d", events)
	}
	if batches != 1 {
		t.Errorf("Expected 1 batch committed by size trigger, got %d", batches)
	}
	if tree.Size() != 50 {
		t.Errorf("Expected MerkleTree size 50, got %d", tree.Size())
	}
}

func TestWorker_FlushByInterval(t *testing.T) {
	q := NewBoundedQueue(1000, nil)
	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	cfg := WorkerConfig{
		BatchSize:         100,
		FlushInterval:     50 * time.Millisecond, // 50ms ticker trigger
		WALReplayInterval: 1 * time.Second,
	}

	worker := NewMicroBatchWorker(cfg, q, client, tree, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)
	defer worker.Stop()

	// Enqueue 10 items (less than BatchSize of 100)
	for i := 0; i < 10; i++ {
		_ = q.Enqueue(&AuditEventEnvelope{
			EventID:       fmt.Sprintf("time-ev-%d", i),
			OutputPayload: "TIME_PAYLOAD",
			Timestamp:     time.Now().UTC(),
		})
	}

	// Sleep 150ms to ensure 50ms ticker fires
	time.Sleep(150 * time.Millisecond)

	events, batches, _ := worker.Stats()
	if events != 10 {
		t.Errorf("Expected 10 events ingested by ticker, got %d", events)
	}
	if batches != 1 {
		t.Errorf("Expected 1 batch flushed by interval, got %d", batches)
	}
	if tree.Size() != 10 {
		t.Errorf("Expected MerkleTree size 10, got %d", tree.Size())
	}
}

func TestWorker_ShutdownDrain(t *testing.T) {
	q := NewBoundedQueue(1000, nil)
	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	cfg := WorkerConfig{
		BatchSize:         100,
		FlushInterval:     10 * time.Second, // Long interval
		WALReplayInterval: 1 * time.Second,
	}

	worker := NewMicroBatchWorker(cfg, q, client, tree, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)

	// Enqueue 35 items
	for i := 0; i < 35; i++ {
		_ = q.Enqueue(&AuditEventEnvelope{
			EventID:       fmt.Sprintf("drain-ev-%d", i),
			OutputPayload: "DRAIN_PAYLOAD",
			Timestamp:     time.Now().UTC(),
		})
	}

	// Trigger shutdown: Worker.Stop() should drain all 35 items
	worker.Stop()

	events, batches, _ := worker.Stats()
	if events != 35 {
		t.Errorf("Expected 35 events drained on shutdown, got %d", events)
	}
	if batches != 1 {
		t.Errorf("Expected 1 final flush on shutdown, got %d", batches)
	}
	if tree.Size() != 35 {
		t.Errorf("Expected MerkleTree size 35, got %d", tree.Size())
	}
}

func TestWorker_WALReplay(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "worker_wal_replay_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	wal, err := NewDiskWAL(tempDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed: %v", err)
	}
	defer wal.Close()

	q := NewBoundedQueue(1000, wal)
	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	// Simulate database offline initially
	client.SetHealthy(false)

	// Write directly to WAL
	for i := 0; i < 20; i++ {
		_ = wal.WriteEvent(&AuditEventEnvelope{
			EventID:       fmt.Sprintf("wal-spool-%d", i),
			OutputPayload: "OFFLINE_SPOOLED",
			Timestamp:     time.Now().UTC(),
		})
	}

	// Rotate WAL segment so it becomes historical and ready for replay
	_ = wal.Rotate()

	cfg := WorkerConfig{
		BatchSize:         100,
		FlushInterval:     50 * time.Millisecond,
		WALReplayInterval: 100 * time.Millisecond, // Quick replay ticker
	}

	worker := NewMicroBatchWorker(cfg, q, client, tree, wal)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)
	defer worker.Stop()

	// Bring database back online
	client.SetHealthy(true)

	// Wait for WAL replay ticker to execute
	time.Sleep(300 * time.Millisecond)

	_, _, replayed := worker.Stats()
	if replayed != 20 {
		t.Errorf("Expected 20 replayed events from WAL, got %d", replayed)
	}
	if client.TotalEvents() != 20 {
		t.Errorf("Expected client to store 20 replayed events, got %d", client.TotalEvents())
	}
}

func TestWorker_HealthStatus(t *testing.T) {
	q := NewBoundedQueue(500, nil)
	client := NewMockImmudbClient()
	worker := NewMicroBatchWorker(DefaultWorkerConfig(), q, client, nil, nil)

	ctx := context.Background()
	h := worker.Health(ctx)
	if h.Status != "UP" || h.ImmudbStatus != "CONNECTED" {
		t.Errorf("Expected UP / CONNECTED health, got %s / %s", h.Status, h.ImmudbStatus)
	}

	// Toggle unhealthy
	client.SetHealthy(false)
	hUnhealthy := worker.Health(ctx)
	if hUnhealthy.Status != "DEGRADED" || hUnhealthy.ImmudbStatus != "DISCONNECTED" {
		t.Errorf("Expected DEGRADED / DISCONNECTED health, got %s / %s", hUnhealthy.Status, hUnhealthy.ImmudbStatus)
	}
}
