package canonical

// DecisionSignPayload represents the canonical payload signed by approvers.
type DecisionSignPayload struct {
	DecisionID       string `json:"decision_id"`
	ApproverID       string `json:"approver_id"`
	Action           string `json:"action"` // "APPROVE" or "REJECT"
	DwellTimeSeconds int    `json:"dwell_time_seconds"`
	Timestamp        string `json:"timestamp"` // ISO 8601 UTC string (RFC 3339)
	ContentHash      string `json:"content_hash,omitempty"`
}
