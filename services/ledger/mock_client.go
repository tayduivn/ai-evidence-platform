package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MockImmudbClient provides a 100% offline, thread-safe in-memory ledger client with tamper simulation.
type MockImmudbClient struct {
	mu               sync.RWMutex
	events           map[string]*AuditEventEnvelope
	correlationIndex map[string][]string // correlation_id -> []event_id
	txHistory        []*BatchCommitResult
	anchors          map[string]*AnchorRecord
	latestAnchorID   string
	currentTxID      uint64
	currentRoot      []byte
	healthy          bool
}

// NewMockImmudbClient initializes an in-memory mock immudb client with a deterministic genesis root.
func NewMockImmudbClient() *MockImmudbClient {
	genesis := sha256.Sum256([]byte("immudb_genesis_state"))
	return &MockImmudbClient{
		events:           make(map[string]*AuditEventEnvelope),
		correlationIndex: make(map[string][]string),
		txHistory:        make([]*BatchCommitResult, 0),
		anchors:          make(map[string]*AnchorRecord),
		currentRoot:      genesis[:],
		healthy:          true,
	}
}

// SetHealthy toggles the mock database connection status for fault injection testing.
func (m *MockImmudbClient) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}

// Open simulates opening an immudb session.
func (m *MockImmudbClient) Open(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.healthy {
		return errors.New("mock immudb: connection refused")
	}
	return nil
}

// Close simulates closing an immudb session.
func (m *MockImmudbClient) Close(ctx context.Context) error {
	return nil
}

// HealthCheck simulates a database ping.
func (m *MockImmudbClient) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return errors.New("mock immudb: service unavailable")
	}
	return nil
}

// CommitBatch atomically commits a micro-batch of events, updating state root and transaction history.
func (m *MockImmudbClient) CommitBatch(ctx context.Context, batch []*AuditEventEnvelope) (*BatchCommitResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.healthy {
		return nil, errors.New("mock immudb: database unreachable")
	}

	if len(batch) == 0 {
		return &BatchCommitResult{
			TxID:        m.currentTxID,
			RootHash:    m.currentRoot,
			CommittedAt: time.Now().UTC(),
			EventCount:  0,
		}, nil
	}

	m.currentTxID++
	h := sha256.New()
	h.Write(m.currentRoot)

	for _, ev := range batch {
		if ev == nil {
			continue
		}
		// Deep copy to prevent outside mutation
		data, _ := json.Marshal(ev)
		var stored AuditEventEnvelope
		_ = json.Unmarshal(data, &stored)

		m.events[ev.EventID] = &stored
		if ev.CorrelationID != "" {
			m.correlationIndex[ev.CorrelationID] = append(m.correlationIndex[ev.CorrelationID], ev.EventID)
		}
		h.Write(data)
	}

	newRoot := h.Sum(nil)
	m.currentRoot = newRoot

	res := &BatchCommitResult{
		TxID:        m.currentTxID,
		RootHash:    newRoot,
		CommittedAt: time.Now().UTC(),
		EventCount:  len(batch),
	}
	m.txHistory = append(m.txHistory, res)
	return res, nil
}

// GetLatestState returns the latest transaction sequence number and state root hash.
func (m *MockImmudbClient) GetLatestState(ctx context.Context) (uint64, []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return 0, nil, errors.New("mock immudb: offline")
	}
	rootCopy := make([]byte, len(m.currentRoot))
	copy(rootCopy, m.currentRoot)
	return m.currentTxID, rootCopy, nil
}

// GetEvent retrieves a stored audit event by event ID.
func (m *MockImmudbClient) GetEvent(ctx context.Context, eventID string) (*AuditEventEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return nil, errors.New("mock immudb: offline")
	}

	ev, ok := m.events[eventID]
	if !ok {
		return nil, fmt.Errorf("event %s not found", eventID)
	}

	// Return a copy
	data, _ := json.Marshal(ev)
	var copyEv AuditEventEnvelope
	_ = json.Unmarshal(data, &copyEv)
	return &copyEv, nil
}

// GetEventsByCorrelation returns all audit events matching a correlation ID.
func (m *MockImmudbClient) GetEventsByCorrelation(ctx context.Context, correlationID string) ([]*AuditEventEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return nil, errors.New("mock immudb: offline")
	}

	eventIDs := m.correlationIndex[correlationID]
	result := make([]*AuditEventEnvelope, 0, len(eventIDs))
	for _, id := range eventIDs {
		if ev, ok := m.events[id]; ok {
			data, _ := json.Marshal(ev)
			var copyEv AuditEventEnvelope
			_ = json.Unmarshal(data, &copyEv)
			result = append(result, &copyEv)
		}
	}
	return result, nil
}

// SaveAnchor persists an RFC 3161 anchor record.
func (m *MockImmudbClient) SaveAnchor(ctx context.Context, anchor *AnchorRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.healthy {
		return errors.New("mock immudb: offline")
	}
	if anchor == nil {
		return errors.New("anchor cannot be nil")
	}

	data, _ := json.Marshal(anchor)
	var copyAnchor AnchorRecord
	_ = json.Unmarshal(data, &copyAnchor)

	m.anchors[anchor.AnchorID] = &copyAnchor
	m.latestAnchorID = anchor.AnchorID
	return nil
}

// GetLatestAnchor returns the most recently saved anchor record.
func (m *MockImmudbClient) GetLatestAnchor(ctx context.Context) (*AnchorRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return nil, errors.New("mock immudb: offline")
	}
	if m.latestAnchorID == "" {
		return nil, errors.New("no anchors recorded")
	}
	anchor := m.anchors[m.latestAnchorID]
	data, _ := json.Marshal(anchor)
	var copyAnchor AnchorRecord
	_ = json.Unmarshal(data, &copyAnchor)
	return &copyAnchor, nil
}

// GetAnchorByID retrieves a specific anchor record by anchor ID.
func (m *MockImmudbClient) GetAnchorByID(ctx context.Context, anchorID string) (*AnchorRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return nil, errors.New("mock immudb: offline")
	}
	anchor, ok := m.anchors[anchorID]
	if !ok {
		return nil, fmt.Errorf("anchor %s not found", anchorID)
	}
	data, _ := json.Marshal(anchor)
	var copyAnchor AnchorRecord
	_ = json.Unmarshal(data, &copyAnchor)
	return &copyAnchor, nil
}

// SimulateTamper modifies a stored event to facilitate adversarial verification testing.
func (m *MockImmudbClient) SimulateTamper(eventID string, corruptedField string, tamperedValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ev, ok := m.events[eventID]
	if !ok {
		return fmt.Errorf("event %s not found for tamper simulation", eventID)
	}

	switch corruptedField {
	case "output_payload":
		ev.OutputPayload = tamperedValue
	case "input_payload":
		ev.InputPayload = tamperedValue
	case "payload_hash":
		ev.PayloadHash = tamperedValue
	case "model_version":
		ev.ModelVersion = tamperedValue
	case "ai_system_id":
		ev.AISystemID = tamperedValue
	default:
		ev.Status = tamperedValue
	}
	return nil
}

// TotalEvents returns the total number of events stored in the mock client.
func (m *MockImmudbClient) TotalEvents() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}

// TotalTransactions returns the total number of committed batches.
func (m *MockImmudbClient) TotalTransactions() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txHistory)
}
