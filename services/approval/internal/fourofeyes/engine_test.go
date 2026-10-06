package fourofeyes

import (
	"errors"
	"testing"
)

func TestFourEyes_CreatorSelfApprovalBlocked(t *testing.T) {
	engine := NewEngine()
	err := engine.ValidateApprovalAction("creator-1", "creator-1", "APPROVE", nil, "", nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrCreatorCannotApprove) {
		t.Errorf("expected ErrCreatorCannotApprove, got: %v", err)
	}
}

func TestFourEyes_DuplicateApproverBlocked(t *testing.T) {
	engine := NewEngine()
	err := engine.ValidateApprovalAction("creator-1", "approver-1", "APPROVE", []string{"approver-1"}, "", nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrDuplicateApprover) {
		t.Errorf("expected ErrDuplicateApprover, got: %v", err)
	}
}

func TestFourEyes_DistinctApproverAllowed(t *testing.T) {
	engine := NewEngine()
	err := engine.ValidateApprovalAction("creator-1", "approver-2", "APPROVE", []string{"approver-1"}, "", nil)
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestFourEyes_RoleHierarchy(t *testing.T) {
	engine := NewEngine()
	requiredRoles := []string{"credit_lead", "cro_risk_officer"}

	// Step 1 with correct role
	err := engine.ValidateApprovalAction("creator-1", "user-1", "APPROVE", nil, "credit_lead", requiredRoles)
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	// Step 1 with wrong role
	err = engine.ValidateApprovalAction("creator-1", "user-1", "APPROVE", nil, "junior_analyst", requiredRoles)
	if err == nil || !errors.Is(err, ErrRoleMismatch) {
		t.Errorf("expected ErrRoleMismatch, got: %v", err)
	}
}
