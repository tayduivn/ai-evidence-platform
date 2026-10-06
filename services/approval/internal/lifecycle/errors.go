package lifecycle

import (
	"fmt"
	"net/http"
)

// ApprovalError represents a structured domain error with HTTP mapping.
type ApprovalError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"error"`
	HTTPStatus int                    `json:"http_status"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

func (e *ApprovalError) Error() string {
	return e.Message
}

func ErrTerminalState(status ApprovalStatus) *ApprovalError {
	return &ApprovalError{
		Code:       "TERMINAL_STATE",
		Message:    fmt.Sprintf("Cannot transition from terminal state %s", status),
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrCreatorCannotApprove() *ApprovalError {
	return &ApprovalError{
		Code:       "CREATOR_CANNOT_APPROVE",
		Message:    "CREATOR_CANNOT_APPROVE: Creator cannot approve their own decision",
		HTTPStatus: http.StatusForbidden,
	}
}

func ErrDuplicateApprover() *ApprovalError {
	return &ApprovalError{
		Code:       "DUPLICATE_APPROVER",
		Message:    "DUPLICATE_APPROVER: Distinct approver required for second approval",
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrDwellTimeNotMet(actual, required int) *ApprovalError {
	return &ApprovalError{
		Code:       "DWELL_TIME_NOT_MET",
		Message:    fmt.Sprintf("DWELL_TIME_NOT_MET: Viewing duration %ds < required %ds", actual, required),
		HTTPStatus: http.StatusUnprocessableEntity,
		Details: map[string]interface{}{
			"required_seconds": required,
			"elapsed_seconds":  actual,
		},
	}
}

func ErrInvalidAction(action ApprovalAction) *ApprovalError {
	return &ApprovalError{
		Code:       "INVALID_ACTION",
		Message:    fmt.Sprintf("Invalid action: %s", action),
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrDecisionExpired() *ApprovalError {
	return &ApprovalError{
		Code:       "DECISION_EXPIRED",
		Message:    "Decision has expired",
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrDecisionNotFound(id string) *ApprovalError {
	return &ApprovalError{
		Code:       "DECISION_NOT_FOUND",
		Message:    fmt.Sprintf("Decision not found: %s", id),
		HTTPStatus: http.StatusNotFound,
	}
}

func ErrOptimisticLock(expected, actual int64) *ApprovalError {
	return &ApprovalError{
		Code:       "CONCURRENT_MODIFICATION",
		Message:    fmt.Sprintf("CONCURRENT_MODIFICATION: Version mismatch (expected %d, actual %d)", expected, actual),
		HTTPStatus: http.StatusConflict,
	}
}

func ErrSignerNotFound(signerType string, err error) *ApprovalError {
	msg := fmt.Sprintf("SIGNER_NOT_FOUND: Signer '%s' not registered", signerType)
	if err != nil {
		msg = fmt.Sprintf("SIGNER_NOT_FOUND: %v", err)
	}
	return &ApprovalError{
		Code:       "SIGNER_NOT_FOUND",
		Message:    msg,
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrSigningFailed(err error) *ApprovalError {
	msg := "SIGNING_FAILED: Digital signing failed"
	if err != nil {
		msg = fmt.Sprintf("SIGNING_FAILED: %v", err)
	}
	return &ApprovalError{
		Code:       "SIGNING_FAILED",
		Message:    msg,
		HTTPStatus: http.StatusInternalServerError,
	}
}

