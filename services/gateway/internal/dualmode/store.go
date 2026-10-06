package dualmode

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrDecisionNotFound = errors.New("decision not found")
)

const (
	StatusPending          = "PENDING"
	StatusPendingApproval  = "PENDING_APPROVAL"
	StatusAwaitingSecond   = "AWAITING_SECOND_APPROVAL"
	StatusApproved         = "APPROVED"
	StatusRejected         = "REJECTED"
	StatusExpired          = "EXPIRED"
)

// DecisionRecord holds the persistent state and audit artifacts of an intercepted decision.
type DecisionRecord struct {
	DecisionID       string                 `json:"decision_id"`
	CorrelationID    string                 `json:"correlation_id"`
	AISystemID       string                 `json:"ai_system_id"`
	SystemType       string                 `json:"system_type"` // "llm" or "ml"
	ModelVersion     string                 `json:"model_version,omitempty"`
	Status           string                 `json:"status"` // "PENDING", ...
	Payload          map[string]interface{} `json:"payload,omitempty"`
	RawInput         string                 `json:"raw_input,omitempty"`
	MaskedInput      string                 `json:"masked_input,omitempty"`
	Score            *float64               `json:"score,omitempty"`
	Decision         string                 `json:"decision,omitempty"`
	Explanation      interface{}            `json:"explanation,omitempty"`
	CreatorID        string                 `json:"creator_id,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ExpiresAt        time.Time              `json:"expires_at"`
}

// DecisionStore defines the contract for persisting intercepted decision records.
type DecisionStore interface {
	Save(record *DecisionRecord) error
	Get(id string) (*DecisionRecord, error)
	UpdateStatus(id string, status string) error
	List() []*DecisionRecord
}

// MemoryDecisionStore is a thread-safe in-memory store for decision records.
type MemoryDecisionStore struct {
	mu      sync.RWMutex
	records map[string]*DecisionRecord
}

// NewMemoryDecisionStore constructs a new MemoryDecisionStore.
func NewMemoryDecisionStore() *MemoryDecisionStore {
	return &MemoryDecisionStore{
		records: make(map[string]*DecisionRecord),
	}
}

// Save persists a new or updated decision record.
func (s *MemoryDecisionStore) Save(record *DecisionRecord) error {
	if record == nil || record.DecisionID == "" {
		return errors.New("invalid decision record")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clone record to prevent external mutation
	clone := *record
	if clone.CreatedAt.IsZero() {
		clone.CreatedAt = time.Now().UTC()
	}
	if clone.UpdatedAt.IsZero() {
		clone.UpdatedAt = clone.CreatedAt
	}
	if clone.ExpiresAt.IsZero() {
		clone.ExpiresAt = clone.CreatedAt.Add(24 * time.Hour)
	}

	s.records[record.DecisionID] = &clone
	return nil
}

// Get retrieves a decision record by ID, automatically evaluating TTL expiration.
func (s *MemoryDecisionStore) Get(id string) (*DecisionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[id]
	if !exists {
		return nil, ErrDecisionNotFound
	}

	clone := *record
	// If still pending/awaiting second approval but past expiration, mark EXPIRED
	if !clone.ExpiresAt.IsZero() && time.Now().UTC().After(clone.ExpiresAt) {
		if clone.Status == StatusPending || clone.Status == StatusPendingApproval || clone.Status == StatusAwaitingSecond {
			clone.Status = StatusExpired
		}
	}

	return &clone, nil
}

// UpdateStatus modifies the lifecycle state of a decision.
func (s *MemoryDecisionStore) UpdateStatus(id string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[id]
	if !exists {
		return ErrDecisionNotFound
	}

	record.Status = status
	record.UpdatedAt = time.Now().UTC()
	return nil
}

// List returns all active decision records.
func (s *MemoryDecisionStore) List() []*DecisionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*DecisionRecord, 0, len(s.records))
	for _, rec := range s.records {
		clone := *rec
		if !clone.ExpiresAt.IsZero() && time.Now().UTC().After(clone.ExpiresAt) {
			if clone.Status == StatusPending || clone.Status == StatusPendingApproval || clone.Status == StatusAwaitingSecond {
				clone.Status = StatusExpired
			}
		}
		list = append(list, &clone)
	}
	return list
}
