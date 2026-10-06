package mlingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/pii"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

// IngestHandler processes ML model decisions and feature data.
type IngestHandler struct {
	queue         ledger.LedgerQueue
	registry      *registry.RegistryManager
	decisionStore dualmode.DecisionStore
}

// NewIngestHandler constructs an IngestHandler.
func NewIngestHandler(
	queue ledger.LedgerQueue,
	rm *registry.RegistryManager,
	store dualmode.DecisionStore,
) *IngestHandler {
	return &IngestHandler{
		queue:         queue,
		registry:      rm,
		decisionStore: store,
	}
}

// ServeHTTP handles POST /api/v1/ml/ingest.
func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}
	_ = r.Body.Close()

	var req MLIngestRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Malformed JSON payload"})
		return
	}

	// 1. Mandatory field validation
	if err := ValidateMLIngestRequest(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 2. AI Registry validation
	status, errMsg, entry := h.registry.EvaluateRequest(req.AISystemID, req.ArtifactHash, "")
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(registry.ErrorResponse{
			Error: errMsg,
		})
		return
	}

	// Correlation ID
	corrID := req.CorrelationID
	if corrID == "" {
		corrID = r.Header.Get("X-Correlation-ID")
	}
	if corrID == "" {
		corrID = "tx-" + uuid.New().String()
	}
	w.Header().Set("X-Correlation-ID", corrID)

	// 3. Vietnamese PII scanning on features map
	maskedFeatures, piiDetected := pii.MaskMapValues(req.Features)

	// Canonical payload hash calculation
	featBytes, _ := json.Marshal(req.Features)
	hSum := sha256.Sum256(featBytes)
	payloadHash := hex.EncodeToString(hSum[:])

	// 4. Dual-mode evaluation
	entryRequiresApproval := entry != nil && entry.RequiresApproval
	mode := dualmode.Evaluate(r.Header.Get(dualmode.HeaderRequireApproval), req.RequiresApproval, entryRequiresApproval)

	if mode == dualmode.ModeIntercept {
		// Intercept & Approve Mode
		decisionID := "dec-ml-" + uuid.New().String()
		pollURL := "/api/v1/decisions/" + decisionID + "/status"

		if h.decisionStore != nil {
			_ = h.decisionStore.Save(&dualmode.DecisionRecord{
				DecisionID:    decisionID,
				CorrelationID: corrID,
				AISystemID:    req.AISystemID,
				SystemType:    "ml",
				ModelVersion:  req.ModelVersion,
				Status:        dualmode.StatusPending,
				Payload:       req.Features,
				Score:         req.Score,
				Decision:      req.Decision,
				Explanation:   req.Explanation,
				CreatorID:     req.CreatorID,
				CreatedAt:     time.Now().UTC(),
				UpdatedAt:     time.Now().UTC(),
			})
		}

		// Enqueue interception audit event non-blockingly
		h.dispatchAuditEvent(&ledger.AuditEventEnvelope{
			EventID:          uuid.New().String(),
			CorrelationID:    corrID,
			Source:           ledger.SourceIngestML,
			AISystemID:       req.AISystemID,
			SystemType:       "ml",
			ModelVersion:     req.ModelVersion,
			CodeOrPromptHash: req.ArtifactHash,
			EventType:        ledger.EventTypeHumanApproval,
			Payload:          maskedFeatures,
			PayloadHash:      payloadHash,
			PIIDetected:      piiDetected,
			PIIFlag:          len(piiDetected) > 0,
			ClientIP:         r.RemoteAddr,
			UserAgent:        r.UserAgent(),
			Status:           dualmode.StatusPendingApproval,
			Timestamp:        time.Now().UTC(),
		})

		w.Header().Set("Location", pollURL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(MLIngestInterceptResponse{
			Status:        "PENDING_APPROVAL",
			DecisionID:    decisionID,
			CorrelationID: corrID,
			PollURL:       pollURL,
		})
		return
	}

	// 5. Audit-Only Mode
	eventID := uuid.New().String()
	h.dispatchAuditEvent(&ledger.AuditEventEnvelope{
		EventID:          eventID,
		CorrelationID:    corrID,
		Source:           ledger.SourceIngestML,
		AISystemID:       req.AISystemID,
		SystemType:       "ml",
		ModelVersion:     req.ModelVersion,
		CodeOrPromptHash: req.ArtifactHash,
		EventType:        ledger.EventTypeMLDecision,
		Payload:          maskedFeatures,
		PayloadHash:      payloadHash,
		PIIDetected:      piiDetected,
		PIIFlag:          len(piiDetected) > 0,
		ClientIP:         r.RemoteAddr,
		UserAgent:        r.UserAgent(),
		Status:           "COMPLETED",
		Timestamp:        time.Now().UTC(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(MLIngestSuccessResponse{
		Status:        "INGESTED",
		EventID:       eventID,
		CorrelationID: corrID,
	})
}

func (h *IngestHandler) dispatchAuditEvent(envelope *ledger.AuditEventEnvelope) {
	if h.queue == nil || envelope == nil {
		return
	}
	go func() {
		_ = h.queue.Enqueue(envelope)
	}()
}
