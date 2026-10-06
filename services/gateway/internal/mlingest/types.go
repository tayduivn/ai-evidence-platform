package mlingest

// MLIngestRequest models the inbound payload on POST /api/v1/ml/ingest.
type MLIngestRequest struct {
	AISystemID       string                 `json:"ai_system_id"`
	ModelVersion     string                 `json:"model_version,omitempty"`
	ArtifactHash     string                 `json:"artifact_hash,omitempty"`
	Features         map[string]interface{} `json:"features,omitempty"`
	Score            *float64               `json:"score"`
	Decision         string                 `json:"decision,omitempty"`
	Explanation      *MLExplanation         `json:"explanation,omitempty"`
	CorrelationID    string                 `json:"correlation_id,omitempty"`
	RequiresApproval bool                   `json:"requires_approval"`
	CreatorID        string                 `json:"creator_id,omitempty"`
}

// MLExplanation encapsulates model explainability outputs (e.g. SHAP values).
type MLExplanation struct {
	Method      string          `json:"method"` // e.g. "SHAP_TreeExplainer"
	TopFeatures []FeatureImpact `json:"top_features"`
}

// FeatureImpact represents the contribution score of an individual feature.
type FeatureImpact struct {
	Feature      string      `json:"feature"`
	Importance   float64     `json:"importance"`
	Contribution string      `json:"contribution,omitempty"`
	Value        interface{} `json:"value,omitempty"`
}

// MLIngestSuccessResponse is returned on successful Audit-Only ingestion.
type MLIngestSuccessResponse struct {
	Status        string `json:"status"`         // "INGESTED"
	EventID       string `json:"event_id"`       // Generated event UUID
	CorrelationID string `json:"correlation_id"` // Transaction correlation ID
}

// MLIngestInterceptResponse is returned on HTTP 202 Accepted when approval is required.
type MLIngestInterceptResponse struct {
	Status        string `json:"status"`         // "PENDING_APPROVAL"
	DecisionID    string `json:"decision_id"`    // e.g. "dec-ml-..."
	CorrelationID string `json:"correlation_id"` // Transaction correlation ID
	PollURL       string `json:"poll_url"`       // e.g. "/api/v1/decisions/{id}/status"
}
