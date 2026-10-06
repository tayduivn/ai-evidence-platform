package lifecycle

import (
	"time"
)

// ApprovalStatus represents the lifecycle state of an approval request.
type ApprovalStatus string

const (
	StatusPending                ApprovalStatus = "PENDING"
	StatusPendingApproval        ApprovalStatus = "PENDING_APPROVAL" // Compatibility alias
	StatusAwaitingSecondApproval ApprovalStatus = "AWAITING_SECOND_APPROVAL"
	StatusApproved               ApprovalStatus = "APPROVED"
	StatusRejected               ApprovalStatus = "REJECTED"
	StatusExpired                ApprovalStatus = "EXPIRED"
)

// ApprovalAction represents the action taken by a human reviewer.
type ApprovalAction string

const (
	ActionApprove ApprovalAction = "APPROVE"
	ActionReject  ApprovalAction = "REJECT"
)

// ApproverAuditRecord stores immutable metadata of an individual approval action.
type ApproverAuditRecord struct {
	ApproverID     string         `json:"approver_id"`
	Role           string         `json:"role,omitempty"`
	Action         ApprovalAction `json:"action"`
	DwellSeconds   int            `json:"dwell_seconds"`
	SignerType     string         `json:"signer_type"`
	SignatureHex   string         `json:"signature_hex,omitempty"`
	SignedPayload  any            `json:"signed_payload,omitempty"`
	CertificatePEM string         `json:"certificate_pem,omitempty"`
	Comment        string         `json:"comment,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// ApprovalDecisionRecord represents the state and context of a decision requiring approval.
type ApprovalDecisionRecord struct {
	DecisionID      string                 `json:"decision_id"`
	CorrelationID   string                 `json:"correlation_id"`
	AISystemID      string                 `json:"ai_system_id"`
	SystemType      string                 `json:"system_type"` // "llm" or "ml"
	ModelVersion    string                 `json:"model_version,omitempty"`
	CreatorID       string                 `json:"creator_id"`
	Status          ApprovalStatus         `json:"status"`
	Requires4Eyes   bool                   `json:"requires_4_eyes"`
	RequiredRoles   []string               `json:"required_roles,omitempty"`
	MinDwellSeconds int                    `json:"min_dwell_seconds"`
	Payload         map[string]interface{} `json:"payload,omitempty"`
	RawInput        string                 `json:"raw_input,omitempty"`
	MaskedInput     string                 `json:"masked_input,omitempty"`
	Score           *float64               `json:"score,omitempty"`
	Decision        string                 `json:"decision,omitempty"`
	Explanation     interface{}            `json:"explanation,omitempty"`
	PIIDetected     []string               `json:"pii_detected,omitempty"`
	Approvals       []ApproverAuditRecord  `json:"approvals"`
	Version         int64                  `json:"version"` // Optimistic concurrency revision
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
}

// ApprovalActionRequest models the inbound payload on POST /api/v1/approvals/{id}/decide.
type ApprovalActionRequest struct {
	ApproverID      string         `json:"approver_id"`
	Role            string         `json:"role,omitempty"`
	Action          ApprovalAction `json:"action"`
	DwellSeconds    int            `json:"dwell_seconds"`
	SignerType      string         `json:"signer_type,omitempty"`
	SignatureHex    string         `json:"signature_hex,omitempty"`
	CertificatePEM  string         `json:"certificate_pem,omitempty"`
	Comment         string         `json:"comment,omitempty"`
	SessionToken    string         `json:"session_token,omitempty"`
	ExpectedVersion int64          `json:"expected_version,omitempty"`
}

// ApprovalActionResponse is returned upon successful action processing.
type ApprovalActionResponse struct {
	Status       ApprovalStatus `json:"status"`
	StatusCode   int            `json:"status_code"`
	Message      string         `json:"message"`
	DecisionID   string         `json:"decision_id"`
	Version      int64          `json:"version"`
	StepIndex    int            `json:"step_index"`
	SignatureHex string         `json:"signature_hex,omitempty"`
}
