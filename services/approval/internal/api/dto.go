package api

import (
	"time"

	"ei-evidence-platform/services/approval/internal/lifecycle"
)

// PendingApprovalsResponse models the response for GET /api/v1/approvals/pending.
type PendingApprovalsResponse struct {
	Items      []ApprovalItemSummary `json:"items"`
	TotalCount int                   `json:"total_count"`
	Limit      int                   `json:"limit"`
	Offset     int                   `json:"offset"`
}

// ApprovalItemSummary models a single item in the pending queue table.
type ApprovalItemSummary struct {
	DecisionID         string                   `json:"decision_id"`
	CorrelationID      string                   `json:"correlation_id"`
	AISystemID         string                   `json:"ai_system_id"`
	SystemType         string                   `json:"system_type"` // "llm" or "ml"
	ModelVersion       string                   `json:"model_version,omitempty"`
	Status             lifecycle.ApprovalStatus `json:"status"`
	RiskTier           string                   `json:"risk_tier"`
	Requires4Eyes      bool                     `json:"requires_4_eyes"`
	CurrentApprovers   int                      `json:"current_approvers"`
	RequiredApprovers  int                      `json:"required_approvers"`
	Score              *float64                 `json:"score,omitempty"`
	DecisionSummary    string                   `json:"decision_summary,omitempty"`
	CreatorID          string                   `json:"creator_id,omitempty"`
	WaitingTimeSeconds int64                    `json:"waiting_time_seconds"`
	CreatedAt          time.Time                `json:"created_at"`
	ExpiresAt          time.Time                `json:"expires_at"`
}

// ApprovalDetail models the response for GET /api/v1/approvals/{id}.
type ApprovalDetail struct {
	DecisionID      string                        `json:"decision_id"`
	CorrelationID   string                        `json:"correlation_id"`
	AISystemID      string                        `json:"ai_system_id"`
	SystemType      string                        `json:"system_type"` // "llm" or "ml"
	ModelVersion    string                        `json:"model_version,omitempty"`
	Status          lifecycle.ApprovalStatus      `json:"status"`
	RiskTier        string                        `json:"risk_tier"`
	CreatorID       string                        `json:"creator_id"`
	CreatedAt       time.Time                     `json:"created_at"`
	UpdatedAt       time.Time                     `json:"updated_at"`
	ExpiresAt       time.Time                     `json:"expires_at"`
	LLMContext      *LLMInspectionContext         `json:"llm_context,omitempty"`
	MLContext       *MLInspectionContext          `json:"ml_context,omitempty"`
	AntiRubberstamp DwellTimePolicy               `json:"anti_rubberstamp"`
	FourEyes        FourEyesProgress              `json:"four_eyes"`
	ApprovalHistory []lifecycle.ApproverAuditRecord `json:"approval_history"`
}

// LLMInspectionContext holds prompt comparison, PII tags, and token diffs.
type LLMInspectionContext struct {
	RawPrompt       string      `json:"raw_prompt"`
	MaskedPrompt    string      `json:"masked_prompt"`
	ResponseContent string      `json:"response_content,omitempty"`
	PIIDetected     []string    `json:"pii_detected"`
	PromptDiffSpans []DiffSpan  `json:"prompt_diff_spans"`
	TokenUsage      *TokenUsage `json:"token_usage,omitempty"`
}

// DiffSpan describes a highlighted span for the prompt diff view.
type DiffSpan struct {
	Type     string `json:"type"`          // "unchanged", "pii_masked", "added", "removed"
	Text     string `json:"text"`
	Tag      string `json:"tag,omitempty"` // "[CCCD]", "[SĐT]", "[STK]"
	Original string `json:"original,omitempty"`
}

// MLInspectionContext holds loan scoring, features table, and SHAP explanation.
type MLInspectionContext struct {
	Features    map[string]interface{} `json:"features"`
	Score       float64                `json:"score"`
	MaxScore    float64                `json:"max_score"`
	Threshold   float64                `json:"threshold"`
	Decision    string                 `json:"decision"`
	AmountVND   *int64                 `json:"amount_vnd,omitempty"`
	Explanation *SHAPExplanation       `json:"explanation,omitempty"`
}

// SHAPExplanation models feature contributions for the waterfall chart.
type SHAPExplanation struct {
	Method      string            `json:"method"` // e.g. "SHAP_TreeExplainer"
	BaseValue   float64           `json:"base_value"`
	OutputScore float64           `json:"output_score"`
	TopFeatures []SHAPFeatureItem `json:"top_features"`
}

// SHAPFeatureItem represents an individual feature bar in the SHAP chart.
type SHAPFeatureItem struct {
	Feature      string  `json:"feature"`
	Value        string  `json:"value"`
	Importance   float64 `json:"importance"`
	Contribution string  `json:"contribution"`
	Direction    string  `json:"direction"` // "positive" or "negative"
}

// DwellTimePolicy contains anti-rubberstamping limits and accumulated telemetry.
type DwellTimePolicy struct {
	MinDwellSeconds    int  `json:"min_dwell_seconds"`
	AccumulatedDwellMs int  `json:"accumulated_dwell_ms"`
	RemainingDwellSecs int  `json:"remaining_dwell_seconds"`
	DwellMet           bool `json:"dwell_met"`
}

// FourEyesProgress details the multi-party approval requirements and status.
type FourEyesProgress struct {
	Requires4Eyes        bool     `json:"requires_4_eyes"`
	RequiredApprovals    int      `json:"required_approvals"`
	CurrentApprovals     int      `json:"current_approvals"`
	CompletedApprovers   []string `json:"completed_approvers"`
	RequiredRoles        []string `json:"required_roles,omitempty"`
	CreatorSeparation    bool     `json:"creator_separation_enforced"`
}

// TokenUsage mirrors gateway token usage metrics.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// DwellHeartbeatRequest is sent by POST /api/v1/approvals/{id}/dwell.
type DwellHeartbeatRequest struct {
	ViewerID      string `json:"viewer_id"`
	SessionID     string `json:"session_id"`
	IncrementalMs int    `json:"incremental_ms"`
	TabFocused    bool   `json:"tab_focused"`
}

// DwellHeartbeatResponse is returned by POST /api/v1/approvals/{id}/dwell.
type DwellHeartbeatResponse struct {
	DecisionID         string `json:"decision_id"`
	AccumulatedDwellMs int64  `json:"accumulated_dwell_ms"`
	MinDwellSeconds    int    `json:"min_dwell_seconds"`
	RemainingSeconds   int    `json:"remaining_seconds"`
	DwellMet           bool   `json:"dwell_met"`
}

// DecideActionRequest is sent by POST /api/v1/approvals/{id}/decide.
type DecideActionRequest struct {
	ApproverID      string                   `json:"approver_id"`
	Role            string                   `json:"role"`
	Action          lifecycle.ApprovalAction `json:"action"` // "APPROVE" or "REJECT"
	SignerType      string                   `json:"signer_type"`
	DwellSeconds    int                      `json:"dwell_seconds"`
	Comment         string                   `json:"comment,omitempty"`
	SessionToken    string                   `json:"session_token,omitempty"`
	ExpectedVersion int64                    `json:"expected_version,omitempty"`
}

// DecideActionResponse is returned by POST /api/v1/approvals/{id}/decide.
type DecideActionResponse struct {
	DecisionID      string                   `json:"decision_id"`
	Status          lifecycle.ApprovalStatus `json:"status"`
	StepIndex       int                      `json:"step_index"`
	Action          lifecycle.ApprovalAction `json:"action"`
	ApproverID      string                   `json:"approver_id"`
	SignerType      string                   `json:"signer_type"`
	SignatureHex    string                   `json:"signature_hex,omitempty"`
	AuditEventID    string                   `json:"audit_event_id,omitempty"`
	CommittedLedger bool                     `json:"committed_ledger"`
	Message         string                   `json:"message"`
	Version         int64                    `json:"version"`
}

// ErrorResponse standardizes error envelopes across all approval endpoints.
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code"`
	Details map[string]interface{} `json:"details,omitempty"`
}
