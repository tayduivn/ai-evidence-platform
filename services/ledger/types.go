package ledger

import (
	"time"
)

// EventType categorizes the audit trail entry.
type EventType string

const (
	EventTypeLLMInference      EventType = "LLM_INFERENCE"
	EventTypeMLDecision        EventType = "ML_DECISION"
	EventTypeHumanApproval     EventType = "HUMAN_APPROVAL"
	EventTypeShadowAIViolation EventType = "SHADOW_AI_VIOLATION"
)

// EventSource identifies the originating subsystem.
type EventSource string

const (
	SourceGatewayLLM EventSource = "gateway_llm"
	SourceIngestML   EventSource = "ingest_ml"
	SourceApprovalUI EventSource = "approval_ui"
)

// TokenUsage holds LLM token consumption metrics.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// AuditEventEnvelope is the standard audit record committed to immudb and Merkle Tree.
type AuditEventEnvelope struct {
	EventID          string                 `json:"event_id"`
	CorrelationID    string                 `json:"correlation_id"`
	Source           EventSource            `json:"source,omitempty"`
	AISystemID       string                 `json:"ai_system_id"`
	SystemType       string                 `json:"system_type,omitempty"`
	ModelVersion     string                 `json:"model_version,omitempty"`
	CodeOrPromptHash string                 `json:"code_or_prompt_hash,omitempty"`
	EventType        EventType              `json:"event_type,omitempty"`
	InputPayload     string                 `json:"input_payload,omitempty"`
	OutputPayload    string                 `json:"output_payload,omitempty"`
	InputMasked      string                 `json:"input_masked,omitempty"`
	OutputMasked     string                 `json:"output_masked,omitempty"`
	Payload          map[string]interface{} `json:"payload,omitempty"`
	PayloadHash      string                 `json:"payload_hash,omitempty"`
	PIIDetected      []string               `json:"pii_detected,omitempty"`
	PIIFlag          bool                   `json:"pii_flag,omitempty"`
	ClientIP         string                 `json:"client_ip,omitempty"`
	UserAgent        string                 `json:"user_agent,omitempty"`
	LatencyMS        int64                  `json:"latency_ms,omitempty"`
	TokensUsage      *TokenUsage            `json:"tokens_usage,omitempty"`
	Status           string                 `json:"status,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
}

// BatchCommitResult is returned following an atomic transaction commit.
type BatchCommitResult struct {
	TxID        uint64    `json:"tx_id"`
	RootHash    []byte    `json:"root_hash"`
	CommittedAt time.Time `json:"committed_at"`
	EventCount  int       `json:"event_count"`
}

// AuditStep represents a single step in the Merkle inclusion audit path.
type AuditStep struct {
	Direction string `json:"direction"` // "left" or "right"
	Hash      string `json:"hash"`      // 64-char lowercase hex SHA-256
}

// InclusionProof represents the complete verifiable audit path for a leaf.
type InclusionProof struct {
	TreeSize  int64       `json:"tree_size"`
	LeafIndex int64       `json:"leaf_index"`
	LeafHash  string      `json:"leaf_hash"`
	RootHash  string      `json:"root_hash"`
	AuditPath []AuditStep `json:"audit_path"`
}

// ConsistencyProof proves that tree at FirstSize is a prefix of tree at SecondSize.
type ConsistencyProof struct {
	FirstSize       int64    `json:"first_size"`
	SecondSize      int64    `json:"second_size"`
	FirstRoot       string   `json:"first_root"`
	SecondRoot      string   `json:"second_root"`
	ConsistencyPath []string `json:"consistency_path"`
}

// AnchorRecord stores external RFC 3161 timestamp anchor details.
type AnchorRecord struct {
	AnchorID          string    `json:"anchor_id"`           // Format: anc-<timestamp>-<seq>
	ImmudbTxID        uint64    `json:"immudb_tx_id"`        // Ledger transaction sequence number
	ImmudbRootHash    string    `json:"immudb_root_hash"`    // Hex-encoded 32-byte Merkle root hash
	TSAURL            string    `json:"tsa_url"`             // Target TSA URL
	TSACertSerial     string    `json:"tsa_cert_serial"`     // Serial number of TSA signing certificate
	TimestampTokenB64 string    `json:"timestamp_token_b64"` // Base64-encoded raw DER TSR token
	VerifiedGenTime   time.Time `json:"verified_gen_time"`   // Certified time extracted from TSTInfo
	Status            string    `json:"status"`              // "VALID", "REVOKED", "TAMPERED"
	CreatedAt         time.Time `json:"created_at"`
}

// HealthStatus reports ledger subsystem availability.
type HealthStatus struct {
	Status         string        `json:"status"`        // "UP", "DEGRADED", "DOWN"
	ImmudbStatus   string        `json:"immudb_status"` // "CONNECTED", "DISCONNECTED"
	QueueLength    int           `json:"queue_length"`
	QueueCapacity  int           `json:"queue_capacity"`
	WALActiveFiles int           `json:"wal_active_files"`
	LastCommitTxID uint64        `json:"last_commit_tx_id"`
	LastCommitTime time.Time     `json:"last_commit_time"`
	LastLatency    time.Duration `json:"last_commit_latency"`
}
