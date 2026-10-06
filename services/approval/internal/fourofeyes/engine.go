package fourofeyes

import (
	"errors"
	"fmt"
)

var (
	ErrCreatorCannotApprove = errors.New("CREATOR_CANNOT_APPROVE: Creator cannot approve their own decision")
	ErrDuplicateApprover   = errors.New("DUPLICATE_APPROVER: Distinct approver required for second approval")
	ErrRoleMismatch        = errors.New("ROLE_MISMATCH: Distinct qualified role required")
)

// Policy defines separation of duties rules for human approval.
type Policy struct {
	RequireTwoDistinctApprovers bool
	ForbidCreatorSelfApproval   bool
	ForbidDuplicateApprover     bool
	EnforceRoleSeparation       bool
}

// Engine implements 4-Eyes rule enforcement.
type Engine struct {
	policy Policy
}

// NewEngine creates an Engine with default strict separation policies.
func NewEngine() *Engine {
	return &Engine{
		policy: Policy{
			RequireTwoDistinctApprovers: true,
			ForbidCreatorSelfApproval:   true,
			ForbidDuplicateApprover:     true,
			EnforceRoleSeparation:       true,
		},
	}
}

// NewEngineWithPolicy creates an Engine with custom policy settings.
func NewEngineWithPolicy(policy Policy) *Engine {
	return &Engine{policy: policy}
}

// ValidateApprovalAction validates creator separation, duplicate approvers, and roles.
func (e *Engine) ValidateApprovalAction(
	creatorID string,
	approverID string,
	action string,
	existingApprovers []string,
	approverRole string,
	requiredRoles []string,
) error {
	// 1. Creator self-approval check
	if e.policy.ForbidCreatorSelfApproval && creatorID != "" && approverID == creatorID {
		return ErrCreatorCannotApprove
	}

	// 2. Duplicate approver check (only on APPROVE)
	if action == "APPROVE" && e.policy.ForbidDuplicateApprover {
		for _, prev := range existingApprovers {
			if prev == approverID {
				return ErrDuplicateApprover
			}
		}
	}

	// 3. Role hierarchy check
	if action == "APPROVE" && e.policy.EnforceRoleSeparation && len(requiredRoles) > 0 {
		stepIdx := len(existingApprovers)
		if stepIdx < len(requiredRoles) {
			expectedRole := requiredRoles[stepIdx]
			if approverRole != "" && expectedRole != "" && approverRole != expectedRole {
				return fmt.Errorf("%w: expected %s, got %s", ErrRoleMismatch, expectedRole, approverRole)
			}
		}
	}

	return nil
}
