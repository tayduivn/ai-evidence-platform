package ledger

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	ErrQueueFull   = errors.New("ledger queue is saturated")
	ErrQueueClosed = errors.New("ledger queue is closed")
)

// LedgerQueue provides non-blocking buffering between API ingress and storage.
type LedgerQueue interface {
	Enqueue(event *AuditEventEnvelope) error
	Events() <-chan *AuditEventEnvelope
	Len() int
	Cap() int
	Close() error
	Stats() QueueStats
}

// QueueStats holds observability counters for the bounded queue.
type QueueStats struct {
	EnqueuedTotal uint64 `json:"enqueued_total"`
	DivertedWAL   uint64 `json:"diverted_wal"`
	DroppedTotal  uint64 `json:"dropped_total"`
	CurrentLength int    `json:"current_length"`
	Capacity      int    `json:"capacity"`
}

// BoundedQueue implements a thread-safe ring-buffer queue with WAL overflow diversion.
type BoundedQueue struct {
	ch            chan *AuditEventEnvelope
	wal           WALManager
	highWaterMark int
	mu            sync.RWMutex
	closed        bool

	enqueuedTotal atomic.Uint64
	divertedWAL   atomic.Uint64
	droppedTotal  atomic.Uint64
}

// NewBoundedQueue constructs a BoundedQueue with a specified capacity and optional WAL fallback.
func NewBoundedQueue(capacity int, wal WALManager) *BoundedQueue {
	if capacity <= 0 {
		capacity = 50000
	}
	return &BoundedQueue{
		ch:            make(chan *AuditEventEnvelope, capacity),
		wal:           wal,
		highWaterMark: int(float64(capacity) * 0.90), // 90% capacity threshold
	}
}

// Enqueue adds an event to the in-memory channel or diverts to WAL if near capacity.
func (q *BoundedQueue) Enqueue(event *AuditEventEnvelope) error {
	if event == nil {
		return errors.New("event cannot be nil")
	}

	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.closed {
		return ErrQueueClosed
	}

	// High-water mark check: If channel is >= 90% full, divert immediately to disk WAL
	if len(q.ch) >= q.highWaterMark && q.wal != nil {
		if err := q.wal.WriteEvent(event); err != nil {
			q.droppedTotal.Add(1)
			return err
		}
		q.divertedWAL.Add(1)
		return nil
	}

	// Try non-blocking push to channel
	select {
	case q.ch <- event:
		q.enqueuedTotal.Add(1)
		return nil
	default:
		// Channel saturated: fall back to WAL
		if q.wal != nil {
			if err := q.wal.WriteEvent(event); err != nil {
				q.droppedTotal.Add(1)
				return err
			}
			q.divertedWAL.Add(1)
			return nil
		}
		q.droppedTotal.Add(1)
		return ErrQueueFull
	}
}

// Events returns the receive-only channel of queued audit events.
func (q *BoundedQueue) Events() <-chan *AuditEventEnvelope {
	return q.ch
}

// Len returns the current count of elements buffered in the channel.
func (q *BoundedQueue) Len() int {
	return len(q.ch)
}

// Cap returns the channel capacity.
func (q *BoundedQueue) Cap() int {
	return cap(q.ch)
}

// Close closes the queue and prevents new enqueues.
func (q *BoundedQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	close(q.ch)
	return nil
}

// Stats returns a snapshot of queue telemetry counters.
func (q *BoundedQueue) Stats() QueueStats {
	return QueueStats{
		EnqueuedTotal: q.enqueuedTotal.Load(),
		DivertedWAL:   q.divertedWAL.Load(),
		DroppedTotal:  q.droppedTotal.Load(),
		CurrentLength: len(q.ch),
		Capacity:      cap(q.ch),
	}
}
