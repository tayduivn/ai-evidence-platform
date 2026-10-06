package dualmode

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestDualMode_Evaluator(t *testing.T) {
	// 1. Default audit-only
	if mode := Evaluate("", false, false); mode != ModeAuditOnly {
		t.Fatalf("expected ModeAuditOnly, got %s", mode)
	}

	// 2. Header triggers
	if mode := Evaluate("true", false, false); mode != ModeIntercept {
		t.Fatalf("expected ModeIntercept on header 'true', got %s", mode)
	}
	if mode := Evaluate("True", false, false); mode != ModeIntercept {
		t.Fatalf("expected ModeIntercept on header 'True', got %s", mode)
	}
	if mode := Evaluate("1", false, false); mode != ModeIntercept {
		t.Fatalf("expected ModeIntercept on header '1', got %s", mode)
	}

	// 3. Body flag trigger
	if mode := Evaluate("", true, false); mode != ModeIntercept {
		t.Fatalf("expected ModeIntercept on body flag, got %s", mode)
	}

	// 4. Registry trigger
	if mode := Evaluate("", false, true); mode != ModeIntercept {
		t.Fatalf("expected ModeIntercept on registry flag, got %s", mode)
	}
}

func TestDecisionStore_SaveAndGet(t *testing.T) {
	store := NewMemoryDecisionStore()
	score := 750.0
	rec := &DecisionRecord{
		DecisionID:    "dec-ml-001",
		CorrelationID: "tx-corr-001",
		AISystemID:    "credit-scoring-xgboost",
		SystemType:    "ml",
		Status:        StatusPending,
		Score:         &score,
		Decision:      "APPROVE_LOAN_500M",
	}

	if err := store.Save(rec); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	fetched, err := store.Get("dec-ml-001")
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if fetched.DecisionID != "dec-ml-001" || fetched.Status != StatusPending {
		t.Fatalf("mismatched record: %+v", fetched)
	}
	if *fetched.Score != 750.0 {
		t.Fatalf("mismatched score: %v", *fetched.Score)
	}
}

func TestDecisionStore_UpdateStatus(t *testing.T) {
	store := NewMemoryDecisionStore()
	rec := &DecisionRecord{
		DecisionID: "dec-ml-002",
		Status:     StatusPending,
	}
	_ = store.Save(rec)

	if err := store.UpdateStatus("dec-ml-002", StatusApproved); err != nil {
		t.Fatalf("unexpected error updating status: %v", err)
	}

	fetched, _ := store.Get("dec-ml-002")
	if fetched.Status != StatusApproved {
		t.Fatalf("expected status %s, got %s", StatusApproved, fetched.Status)
	}
}

func TestDecisionStore_NotFound(t *testing.T) {
	store := NewMemoryDecisionStore()
	_, err := store.Get("non-existent")
	if err != ErrDecisionNotFound {
		t.Fatalf("expected ErrDecisionNotFound, got %v", err)
	}

	err = store.UpdateStatus("non-existent", StatusApproved)
	if err != ErrDecisionNotFound {
		t.Fatalf("expected ErrDecisionNotFound on update, got %v", err)
	}
}

func TestDecisionStore_TTLExpiration(t *testing.T) {
	store := NewMemoryDecisionStore()
	rec := &DecisionRecord{
		DecisionID: "dec-ml-expired",
		Status:     StatusPending,
		ExpiresAt:  time.Now().UTC().Add(-1 * time.Minute), // expired in past
	}
	_ = store.Save(rec)

	fetched, err := store.Get("dec-ml-expired")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetched.Status != StatusExpired {
		t.Fatalf("expected status %s for expired record, got %s", StatusExpired, fetched.Status)
	}
}

func TestDecisionStore_Concurrency(t *testing.T) {
	store := NewMemoryDecisionStore()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rec := &DecisionRecord{
				DecisionID:    "dec-concurrent-" + string(rune('a'+id%26)),
				CorrelationID: "tx-conc",
				Status:        StatusPending,
			}
			_ = store.Save(rec)
			_, _ = store.Get(rec.DecisionID)
			_ = store.List()
		}(i)
	}

	wg.Wait()
}

func TestDecisionStatusHandler_HTTP(t *testing.T) {
	store := NewMemoryDecisionStore()
	rec := &DecisionRecord{
		DecisionID:    "dec-test-http",
		CorrelationID: "tx-test-http",
		AISystemID:    "credit-advisor-v1",
		Status:        StatusPending,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	_ = store.Save(rec)

	r := chi.NewRouter()
	r.Get("/api/v1/decisions/{id}/status", NewDecisionStatusHandler(store))

	// 1. Success 200
	req := httptest.NewRequest("GET", "/api/v1/decisions/dec-test-http/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	var resp DecisionStatusResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.DecisionID != "dec-test-http" || resp.Status != StatusPending {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// 2. Not found 404
	req = httptest.NewRequest("GET", "/api/v1/decisions/unknown-id/status", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rr.Code)
	}
}
