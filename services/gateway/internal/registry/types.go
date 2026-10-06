package registry

type contextKey string

const (
	SystemEntryContextKey contextKey = "ai_system_entry"

	HeaderAISystemID     = "X-AI-System-ID"
	HeaderAIArtifactHash = "X-AI-Artifact-Hash"
	HeaderAIPromptHash   = "X-AI-Prompt-Hash"
)

// SystemEntry defines an authorized AI system registration record.
type SystemEntry struct {
	SystemID           string `json:"system_id"`
	ModelVersion       string `json:"model_version,omitempty"`
	RiskLevel          string `json:"risk_level,omitempty"`
	SystemType         string `json:"system_type,omitempty"` // "llm" or "ml"
	RequiresApproval   bool   `json:"requires_approval"`
	ArtifactHash       string `json:"artifact_hash,omitempty"`
	ExpectedPromptHash string `json:"expected_prompt_hash,omitempty"`
	Owner              string `json:"owner,omitempty"`
}

// ErrorResponse formats JSON 403 error payloads for Shadow AI.
type ErrorResponse struct {
	Error string `json:"error"`
}
