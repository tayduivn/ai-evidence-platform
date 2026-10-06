package ledger

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerConfig defines operational parameters for the micro-batch worker.
type WorkerConfig struct {
	BatchSize         int           `json:"batch_size"`           // Default: 100
	FlushInterval     time.Duration `json:"flush_interval"`       // Default: 50ms
	WALReplayInterval time.Duration `json:"wal_replay_interval"`   // Default: 1s
}

// DefaultWorkerConfig returns production defaults for micro-batching.
func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		BatchSize:         100,
		FlushInterval:     50 * time.Millisecond,
		WALReplayInterval: 1 * time.Second,
	}
}

// MicroBatchWorker orchestrates bounded queue consumption, Merkle tree growth, and immudb batch commits.
type MicroBatchWorker struct {
	cfg        WorkerConfig
	queue      LedgerQueue
	client     ImmudbClient
	tree       MerkleTree
	wal        WALManager
	mu         sync.RWMutex
	running    bool
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup

	// Telemetry metrics
	eventsIngested atomic.Uint64
	batchesFlushed atomic.Uint64
	walReplayed    atomic.Uint64
	lastCommitTxID atomic.Uint64
	lastCommitTime atomic.Pointer[time.Time]
	lastLatency    atomic.Int64 // nanoseconds
}

// NewMicroBatchWorker constructs a new worker.
func NewMicroBatchWorker(cfg WorkerConfig, queue LedgerQueue, client ImmudbClient, tree MerkleTree, wal WALManager) *MicroBatchWorker {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 50 * time.Millisecond
	}
	if cfg.WALReplayInterval <= 0 {
		cfg.WALReplayInterval = 1 * time.Second
	}
	if tree == nil {
		tree = NewMemoryMerkleTree()
	}

	w := &MicroBatchWorker{
		cfg:    cfg,
		queue:  queue,
		client: client,
		tree:   tree,
		wal:    wal,
	}
	now := time.Now().UTC()
	w.lastCommitTime.Store(&now)
	return w
}

// Start launches the flusher and WAL replay goroutines.
func (w *MicroBatchWorker) Start(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running {
		return
	}
	w.running = true

	workerCtx, cancel := context.WithCancel(ctx)
	w.cancelFunc = cancel

	w.wg.Add(1)
	go w.runFlusher(workerCtx)

	if w.wal != nil {
		w.wg.Add(1)
		go w.runWALReplay(workerCtx)
	}
}

// Stop initiates graceful shutdown, drains remaining queue events, and waits for loops to exit.
func (w *MicroBatchWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	if w.cancelFunc != nil {
		w.cancelFunc()
	}
	w.mu.Unlock()

	w.wg.Wait()
}

func (w *MicroBatchWorker) runFlusher(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]*AuditEventEnvelope, 0, w.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.commitBatch(batch)
		batch = make([]*AuditEventEnvelope, 0, w.cfg.BatchSize)
	}

	for {
		select {
		case <-ctx.Done():
			// Context cancelled: Drain remaining events in channel
			if w.queue != nil {
				for w.queue.Len() > 0 {
					select {
					case ev, ok := <-w.queue.Events():
						if ok && ev != nil {
							batch = append(batch, ev)
							if len(batch) >= w.cfg.BatchSize {
								flush()
							}
						}
					default:
						break
					}
				}
			}
			flush()
			return

		case ev, ok := <-w.queue.Events():
			if !ok {
				flush()
				return
			}
			if ev != nil {
				batch = append(batch, ev)
				if len(batch) >= w.cfg.BatchSize {
					flush()
				}
			}

		case <-ticker.C:
			if len(batch) > 0 {
				flush()
			}
		}
	}
}

func (w *MicroBatchWorker) commitBatch(batch []*AuditEventEnvelope) {
	start := time.Now()

	// 1. Commit batch to immudb first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := w.client.CommitBatch(ctx, batch)
	duration := time.Since(start)
	w.lastLatency.Store(int64(duration))

	if err != nil {
		// If immudb commit fails, spool batch to WAL to avoid data loss.
		// Note: Leaves are NOT appended to Merkle tree yet, preventing duplication upon replay.
		if w.wal != nil {
			for _, ev := range batch {
				_ = w.wal.WriteEvent(ev)
			}
		}
		return
	}

	// 2. Commit to ledger succeeded: append leaves into Merkle Tree
	rawLeaves := make([][]byte, 0, len(batch))
	for _, ev := range batch {
		raw, _ := json.Marshal(ev)
		rawLeaves = append(rawLeaves, raw)
	}
	_, _, _, _ = w.tree.AppendBatch(rawLeaves)

	w.eventsIngested.Add(uint64(len(batch)))
	w.batchesFlushed.Add(1)
	if res != nil {
		w.lastCommitTxID.Store(res.TxID)
		now := res.CommittedAt
		w.lastCommitTime.Store(&now)
	}
}

func (w *MicroBatchWorker) runWALReplay(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.cfg.WALReplayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if client is healthy
			checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := w.client.HealthCheck(checkCtx)
			cancel()
			if err != nil {
				continue
			}

			// Replay pending segments
			replayed, _ := w.wal.ReplayPending(func(batch []*AuditEventEnvelope) error {
				if len(batch) == 0 {
					return nil
				}
				w.commitBatch(batch)
				return nil
			})
			if replayed > 0 {
				w.walReplayed.Add(uint64(replayed))
			}
		}
	}
}

// Tree returns the underlying Merkle Tree instance.
func (w *MicroBatchWorker) Tree() MerkleTree {
	return w.tree
}

// Health evaluates and returns the health status of the ledger worker subsystem.
func (w *MicroBatchWorker) Health(ctx context.Context) HealthStatus {
	immuStatus := "CONNECTED"
	if err := w.client.HealthCheck(ctx); err != nil {
		immuStatus = "DISCONNECTED"
	}

	status := "UP"
	if immuStatus == "DISCONNECTED" {
		status = "DEGRADED"
	}

	walActive := 0
	if w.wal != nil {
		walActive = w.wal.ActiveSegmentFiles()
	}

	lastTime := time.Time{}
	if t := w.lastCommitTime.Load(); t != nil {
		lastTime = *t
	}

	qLen := 0
	qCap := 0
	if w.queue != nil {
		qLen = w.queue.Len()
		qCap = w.queue.Cap()
	}

	return HealthStatus{
		Status:         status,
		ImmudbStatus:   immuStatus,
		QueueLength:    qLen,
		QueueCapacity:  qCap,
		WALActiveFiles: walActive,
		LastCommitTxID: w.lastCommitTxID.Load(),
		LastCommitTime: lastTime,
		LastLatency:    time.Duration(w.lastLatency.Load()),
	}
}

// FlushImmediate forces a synchronous flush of currently queued events (useful in tests).
func (w *MicroBatchWorker) FlushImmediate() {
	if w.queue == nil {
		return
	}
	batch := make([]*AuditEventEnvelope, 0, w.cfg.BatchSize)
	for w.queue.Len() > 0 {
		select {
		case ev, ok := <-w.queue.Events():
			if ok && ev != nil {
				batch = append(batch, ev)
				if len(batch) >= w.cfg.BatchSize {
					w.commitBatch(batch)
					batch = make([]*AuditEventEnvelope, 0, w.cfg.BatchSize)
				}
			}
		default:
			break
		}
	}
	if len(batch) > 0 {
		w.commitBatch(batch)
	}
}

// Stats returns worker telemetry metrics.
func (w *MicroBatchWorker) Stats() (events uint64, batches uint64, replayed uint64) {
	return w.eventsIngested.Load(), w.batchesFlushed.Load(), w.walReplayed.Load()
}
