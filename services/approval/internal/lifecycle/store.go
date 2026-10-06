package lifecycle

import (
	"errors"
	"sync"
	"time"
)

// ApprovalStore defines the contract for persisting approval decisions.
type ApprovalStore interface {
	Save(record *ApprovalDecisionRecord) error
	Get(id string) (*ApprovalDecisionRecord, error)
	UpdateStatus(id string, status ApprovalStatus) error
	List() []*ApprovalDecisionRecord
	Delete(id string) error
}

// MemoryApprovalStore provides a thread-safe in-memory store for approval decisions.
type MemoryApprovalStore struct {
	mu      sync.RWMutex
	records map[string]*ApprovalDecisionRecord
}

// NewMemoryApprovalStore constructs an in-memory approval store.
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{
		records: make(map[string]*ApprovalDecisionRecord),
	}
}

// Save stores or updates an approval decision record with defensive copy.
func (s *MemoryApprovalStore) Save(record *ApprovalDecisionRecord) error {
	if record == nil || record.DecisionID == "" {
		return errors.New("approval_store: invalid decision record")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	clone := cloneRecord(record)
	now := time.Now().UTC()
	if clone.CreatedAt.IsZero() {
		clone.CreatedAt = now
	}
	if clone.UpdatedAt.IsZero() {
		clone.UpdatedAt = now
	}
	if clone.ExpiresAt.IsZero() {
		clone.ExpiresAt = clone.CreatedAt.Add(24 * time.Hour)
	}

	s.records[record.DecisionID] = clone
	return nil
}

// Get retrieves a decision record by ID, automatically evaluating TTL expiration.
func (s *MemoryApprovalStore) Get(id string) (*ApprovalDecisionRecord, error) {
	s.mu.RLock()
	record, exists := s.records[id]
	if !exists {
		s.mu.RUnlock()
		return nil, ErrDecisionNotFound(id)
	}

	// Check expiration
	if !record.ExpiresAt.IsZero() && time.Now().UTC().After(record.ExpiresAt) &&
		record.Status != StatusApproved && record.Status != StatusRejected && record.Status != StatusExpired {
		s.mu.RUnlock()

		// Upgrade to write lock to mark expired
		s.mu.Lock()
		if rec, stillExists := s.records[id]; stillExists && !rec.ExpiresAt.IsZero() && time.Now().UTC().After(rec.ExpiresAt) {
			rec.Status = StatusExpired
			rec.UpdatedAt = time.Now().UTC()
		}
		record = s.records[id]
		s.mu.Unlock()

		return cloneRecord(record), nil
	}
	s.mu.RUnlock()

	return cloneRecord(record), nil
}

// UpdateStatus updates the status of an existing decision record.
func (s *MemoryApprovalStore) UpdateStatus(id string, status ApprovalStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[id]
	if !exists {
		return ErrDecisionNotFound(id)
	}

	record.Status = status
	record.UpdatedAt = time.Now().UTC()
	return nil
}

// List returns copies of all decision records.
func (s *MemoryApprovalStore) List() []*ApprovalDecisionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*ApprovalDecisionRecord, 0, len(s.records))
	now := time.Now().UTC()
	for _, rec := range s.records {
		clone := cloneRecord(rec)
		if !clone.ExpiresAt.IsZero() && now.After(clone.ExpiresAt) &&
			clone.Status != StatusApproved && clone.Status != StatusRejected && clone.Status != StatusExpired {
			clone.Status = StatusExpired
		}
		list = append(list, clone)
	}
	return list
}

// Delete removes a record from the store.
func (s *MemoryApprovalStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

func cloneRecord(r *ApprovalDecisionRecord) *ApprovalDecisionRecord {
	if r == nil {
		return nil
	}
	c := *r
	if r.Score != nil {
		scoreVal := *r.Score
		c.Score = &scoreVal
	}
	if len(r.RequiredRoles) > 0 {
		c.RequiredRoles = append([]string(nil), r.RequiredRoles...)
	}
	if len(r.PIIDetected) > 0 {
		c.PIIDetected = append([]string(nil), r.PIIDetected...)
	}
	if len(r.Approvals) > 0 {
		c.Approvals = append([]ApproverAuditRecord(nil), r.Approvals...)
	}
	if r.Payload != nil {
		c.Payload = make(map[string]interface{}, len(r.Payload))
		for k, v := range r.Payload {
			c.Payload[k] = v
		}
	}
	return &c
}
