package lifecycle

import (
	"testing"
	"time"
)

func TestStore_ScorePointerDeepCopy(t *testing.T) {
	store := NewMemoryApprovalStore()

	scoreVal := 850.5
	origRecord := &ApprovalDecisionRecord{
		DecisionID:    "dec-score-test",
		Score:         &scoreVal,
		RequiredRoles: []string{"risk_officer"},
		PIIDetected:   []string{"cccd"},
		Payload: map[string]interface{}{
			"amount": 1000000,
		},
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Save(origRecord); err != nil {
		t.Fatalf("failed to save initial record: %v", err)
	}

	// Retrieve first clone
	r1, err := store.Get("dec-score-test")
	if err != nil {
		t.Fatalf("failed to get record: %v", err)
	}
	if r1.Score == nil || *r1.Score != 850.5 {
		t.Fatalf("expected score 850.5, got %v", r1.Score)
	}

	// Mutate r1's score pointer value and slice/map
	*r1.Score = 999.0
	r1.RequiredRoles[0] = "mutated_role"
	r1.Payload["amount"] = 9999999

	// Retrieve second clone from store
	r2, err := store.Get("dec-score-test")
	if err != nil {
		t.Fatalf("failed to get second clone: %v", err)
	}

	// Verify r2 is unaffected by r1's mutations
	if r2.Score == nil || *r2.Score != 850.5 {
		t.Errorf("store record Score mutated: expected 850.5, got %v", r2.Score)
	}
	if r1.Score == r2.Score {
		t.Errorf("r1.Score and r2.Score share the same pointer address %p", r1.Score)
	}
	if r2.RequiredRoles[0] != "risk_officer" {
		t.Errorf("store record RequiredRoles mutated: expected risk_officer, got %s", r2.RequiredRoles[0])
	}
	if r2.Payload["amount"] != 1000000 {
		t.Errorf("store record Payload mutated: expected 1000000, got %v", r2.Payload["amount"])
	}
}

func TestStore_NilScoreHandling(t *testing.T) {
	store := NewMemoryApprovalStore()

	origRecord := &ApprovalDecisionRecord{
		DecisionID: "dec-nil-score",
		Score:      nil,
		Status:     StatusPending,
	}

	if err := store.Save(origRecord); err != nil {
		t.Fatalf("failed to save record with nil score: %v", err)
	}

	r, err := store.Get("dec-nil-score")
	if err != nil {
		t.Fatalf("failed to get record: %v", err)
	}
	if r.Score != nil {
		t.Errorf("expected nil score, got %v", r.Score)
	}
}
