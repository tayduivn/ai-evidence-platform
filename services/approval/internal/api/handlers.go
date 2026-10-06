package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"ei-evidence-platform/services/approval/internal/canonical"
	"ei-evidence-platform/services/approval/internal/lifecycle"
	"ei-evidence-platform/services/ledger"
)

// DecisionStatusUpdater defines the contract for synchronizing status with an external store (e.g. gateway.MemoryDecisionStore).
type DecisionStatusUpdater interface {
	UpdateStatus(id string, status string) error
}

// Service encapsulates the dependencies of the Approval HTTP REST API.
type Service struct {
	StateMachine *lifecycle.ApprovalStateMachine
	GatewayStore DecisionStatusUpdater // Optional integration with gateway DecisionStore
	LedgerQueue  ledger.LedgerQueue     // Optional integration with ledger queue
}

// NewService constructs an API Service.
func NewService(sm *lifecycle.ApprovalStateMachine, gatewayStore DecisionStatusUpdater, ledgerQueue ledger.LedgerQueue) *Service {
	return &Service{
		StateMachine: sm,
		GatewayStore: gatewayStore,
		LedgerQueue:  ledgerQueue,
	}
}

// HealthHandler returns liveness status.
func HealthHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	}
}

// ReadyHandler returns readiness status.
func ReadyHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ready",
		})
	}
}

// ListPendingApprovalsHandler returns all decisions currently awaiting review.
func ListPendingApprovalsHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records := s.StateMachine.GetStore().List()

		systemTypeFilter := r.URL.Query().Get("system_type")
		statusFilter := r.URL.Query().Get("status")
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		}

		now := time.Now().UTC()
		var matched []ApprovalItemSummary

		for _, rec := range records {
			// Filter by status (default: active pending states)
			if statusFilter != "" {
				if string(rec.Status) != statusFilter {
					continue
				}
			} else {
				if rec.Status != lifecycle.StatusPending &&
					rec.Status != lifecycle.StatusPendingApproval &&
					rec.Status != lifecycle.StatusAwaitingSecondApproval {
					continue
				}
			}

			// Filter by system_type
			if systemTypeFilter != "" && rec.SystemType != systemTypeFilter {
				continue
			}

			riskTier := "STANDARD"
			if rec.Requires4Eyes {
				riskTier = "HIGH"
			}
			if rec.Score != nil && *rec.Score > 750 {
				riskTier = "HIGH"
			}
			if len(rec.PIIDetected) > 0 {
				riskTier = "CRITICAL"
			}

			waitingSec := int64(0)
			if !rec.CreatedAt.IsZero() {
				waitingSec = int64(now.Sub(rec.CreatedAt).Seconds())
				if waitingSec < 0 {
					waitingSec = 0
				}
			}

			reqApprovers := 1
			if rec.Requires4Eyes {
				reqApprovers = 2
			}

			matched = append(matched, ApprovalItemSummary{
				DecisionID:         rec.DecisionID,
				CorrelationID:      rec.CorrelationID,
				AISystemID:         rec.AISystemID,
				SystemType:         rec.SystemType,
				ModelVersion:       rec.ModelVersion,
				Status:             rec.Status,
				RiskTier:           riskTier,
				Requires4Eyes:      rec.Requires4Eyes,
				CurrentApprovers:   len(rec.Approvals),
				RequiredApprovers:  reqApprovers,
				Score:              rec.Score,
				DecisionSummary:    rec.Decision,
				CreatorID:          rec.CreatorID,
				WaitingTimeSeconds: waitingSec,
				CreatedAt:          rec.CreatedAt,
				ExpiresAt:          rec.ExpiresAt,
			})
		}

		total := len(matched)
		var paged []ApprovalItemSummary
		if offset < total {
			end := offset + limit
			if end > total {
				end = total
			}
			paged = matched[offset:end]
		} else {
			paged = []ApprovalItemSummary{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PendingApprovalsResponse{
			Items:      paged,
			TotalCount: total,
			Limit:      limit,
			Offset:     offset,
		})
	}
}

// GetApprovalDetailHandler returns the full decision inspection context.
func GetApprovalDetailHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		record, err := s.StateMachine.GetStore().Get(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "DECISION_NOT_FOUND", err.Error(), nil)
			return
		}

		riskTier := "STANDARD"
		if record.Requires4Eyes {
			riskTier = "HIGH"
		}
		if record.Score != nil && *record.Score > 750 {
			riskTier = "HIGH"
		}
		if len(record.PIIDetected) > 0 {
			riskTier = "CRITICAL"
		}

		minDwell := record.MinDwellSeconds
		if minDwell <= 0 {
			minDwell = 10
		}

		// Dwell telemetry from engine
		accumSec := s.StateMachine.GetDwellEngine().GetAccumulatedSeconds(record.DecisionID)
		remainingDwell := minDwell - accumSec
		dwellMet := remainingDwell <= 0
		if remainingDwell < 0 {
			remainingDwell = 0
		}

		// 4-Eyes progress
		reqApprovals := 1
		if record.Requires4Eyes {
			reqApprovals = 2
		}
		completedApprovers := make([]string, 0, len(record.Approvals))
		for _, a := range record.Approvals {
			completedApprovers = append(completedApprovers, a.ApproverID)
		}

		detail := ApprovalDetail{
			DecisionID:    record.DecisionID,
			CorrelationID: record.CorrelationID,
			AISystemID:    record.AISystemID,
			SystemType:    record.SystemType,
			ModelVersion:  record.ModelVersion,
			Status:        record.Status,
			RiskTier:      riskTier,
			CreatorID:     record.CreatorID,
			CreatedAt:     record.CreatedAt,
			UpdatedAt:     record.UpdatedAt,
			ExpiresAt:     record.ExpiresAt,
			AntiRubberstamp: DwellTimePolicy{
				MinDwellSeconds:    minDwell,
				AccumulatedDwellMs: accumSec * 1000,
				RemainingDwellSecs: remainingDwell,
				DwellMet:           dwellMet,
			},
			FourEyes: FourEyesProgress{
				Requires4Eyes:      record.Requires4Eyes,
				RequiredApprovals:  reqApprovals,
				CurrentApprovals:   len(record.Approvals),
				CompletedApprovers: completedApprovers,
				RequiredRoles:      record.RequiredRoles,
				CreatorSeparation:  true,
			},
			ApprovalHistory: record.Approvals,
		}

		// Populate LLM Context
		if record.SystemType == "llm" || record.RawInput != "" || record.MaskedInput != "" {
			diffSpans := buildDiffSpans(record.RawInput, record.MaskedInput, record.PIIDetected)
			detail.LLMContext = &LLMInspectionContext{
				RawPrompt:       record.RawInput,
				MaskedPrompt:    record.MaskedInput,
				PIIDetected:     record.PIIDetected,
				PromptDiffSpans: diffSpans,
			}
		}

		// Populate ML Context
		if record.SystemType == "ml" || record.Score != nil || record.Explanation != nil {
			var shapExpl *SHAPExplanation
			if record.Explanation != nil {
				shapExpl = parseSHAPExplanation(record.Explanation)
			}
			scoreVal := float64(0)
			if record.Score != nil {
				scoreVal = *record.Score
			}
			detail.MLContext = &MLInspectionContext{
				Features:    record.Payload,
				Score:       scoreVal,
				MaxScore:    1000.0,
				Threshold:   650.0,
				Decision:    record.Decision,
				Explanation: shapExpl,
			}
			if amount, ok := record.Payload["amount_vnd"].(float64); ok {
				amtInt := int64(amount)
				detail.MLContext.AmountVND = &amtInt
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detail)
	}
}

// RecordDwellHeartbeatHandler records viewport telemetry for anti-rubberstamping.
func RecordDwellHeartbeatHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		record, err := s.StateMachine.GetStore().Get(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "DECISION_NOT_FOUND", err.Error(), nil)
			return
		}

		var req DwellHeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON payload", nil)
			return
		}

		accumMS, _, _, _ := s.StateMachine.GetDwellEngine().RecordHeartbeat(
			req.SessionID,
			record.DecisionID,
			req.ViewerID,
			req.IncrementalMs,
			req.TabFocused,
		)

		minDwell := record.MinDwellSeconds
		if minDwell <= 0 {
			minDwell = 10
		}

		accumSec := int(accumMS / 1000)
		remainingSec := minDwell - accumSec
		dwellMet := remainingSec <= 0
		if remainingSec < 0 {
			remainingSec = 0
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DwellHeartbeatResponse{
			DecisionID:         record.DecisionID,
			AccumulatedDwellMs: accumMS,
			MinDwellSeconds:    minDwell,
			RemainingSeconds:   remainingSec,
			DwellMet:           dwellMet,
		})
	}
}

// SubmitDecisionActionHandler processes human approval or rejection with digital signatures.
func SubmitDecisionActionHandler(s *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		var req DecideActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON request", nil)
			return
		}

		actionReq := &lifecycle.ApprovalActionRequest{
			ApproverID:      req.ApproverID,
			Role:            req.Role,
			Action:          req.Action,
			DwellSeconds:    req.DwellSeconds,
			SignerType:      req.SignerType,
			Comment:         req.Comment,
			SessionToken:    req.SessionToken,
			ExpectedVersion: req.ExpectedVersion,
		}

		resp, err := s.StateMachine.SubmitAction(r.Context(), id, actionReq)
		if err != nil {
			var appErr *lifecycle.ApprovalError
			if errors.As(err, &appErr) {
				respondError(w, appErr.HTTPStatus, appErr.Code, appErr.Message, appErr.Details)
				return
			}
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), nil)
			return
		}

		// Retrieve latest record for integration sync
		updatedRecord, _ := s.StateMachine.GetStore().Get(id)

		// 1. Sync with gateway.DecisionStore if present
		if s.GatewayStore != nil && updatedRecord != nil {
			_ = s.GatewayStore.UpdateStatus(id, string(updatedRecord.Status))
		}

		// 2. Dispatch audit event to ledger queue if present
		auditEventID := uuid.New().String()
		committedLedger := false

		if s.LedgerQueue != nil && updatedRecord != nil {
			payloadMap := map[string]interface{}{
				"decision_id":   updatedRecord.DecisionID,
				"action":        string(req.Action),
				"approver_id":   req.ApproverID,
				"role":          req.Role,
				"signer_type":   req.SignerType,
				"dwell_seconds": req.DwellSeconds,
				"signature_hex": resp.SignatureHex,
				"new_status":    string(resp.Status),
				"step_index":    resp.StepIndex,
				"comment":       req.Comment,
			}

			canonBytes, _ := canonical.Marshal(payloadMap)
			hash := sha256.Sum256(canonBytes)
			payloadHash := hex.EncodeToString(hash[:])

			envelope := &ledger.AuditEventEnvelope{
				EventID:       auditEventID,
				CorrelationID: updatedRecord.CorrelationID,
				Source:        ledger.SourceApprovalUI,
				AISystemID:    updatedRecord.AISystemID,
				SystemType:    updatedRecord.SystemType,
				ModelVersion:  updatedRecord.ModelVersion,
				EventType:     ledger.EventTypeHumanApproval,
				Payload:       payloadMap,
				PayloadHash:   payloadHash,
				Status:        string(resp.Status),
				Timestamp:     time.Now().UTC(),
			}

			if qErr := s.LedgerQueue.Enqueue(envelope); qErr == nil {
				committedLedger = true
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecideActionResponse{
			DecisionID:      resp.DecisionID,
			Status:          resp.Status,
			StepIndex:       resp.StepIndex,
			Action:          req.Action,
			ApproverID:      req.ApproverID,
			SignerType:      req.SignerType,
			SignatureHex:    resp.SignatureHex,
			AuditEventID:    auditEventID,
			CommittedLedger: committedLedger,
			Message:         resp.Message,
			Version:         resp.Version,
		})
	}
}

func respondError(w http.ResponseWriter, status int, code, msg string, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:   msg,
		Code:    code,
		Details: details,
	})
}

func buildDiffSpans(raw, masked string, piiDetected []string) []DiffSpan {
	if raw == "" && masked == "" {
		return nil
	}
	if raw == masked {
		return []DiffSpan{{Type: "unchanged", Text: raw}}
	}

	// Simple span detection based on masked characters or tags
	var spans []DiffSpan
	tag := "[PII]"
	if len(piiDetected) > 0 {
		tag = "[" + strings.Join(piiDetected, ",") + "]"
	}

	spans = append(spans, DiffSpan{
		Type:     "pii_masked",
		Text:     masked,
		Tag:      tag,
		Original: raw,
	})
	return spans
}

func parseSHAPExplanation(explanation any) *SHAPExplanation {
	if explanation == nil {
		return nil
	}
	// Try parsing map or struct
	bytesData, err := json.Marshal(explanation)
	if err != nil {
		return nil
	}
	var shap SHAPExplanation
	if err := json.Unmarshal(bytesData, &shap); err == nil && len(shap.TopFeatures) > 0 {
		return &shap
	}

	// If explanation is a generic map with top_features
	var m struct {
		Method      string            `json:"method"`
		BaseValue   float64           `json:"base_value"`
		OutputScore float64           `json:"output_score"`
		TopFeatures []json.RawMessage `json:"top_features"`
	}
	if err := json.Unmarshal(bytesData, &m); err == nil {
		expl := &SHAPExplanation{
			Method:      m.Method,
			BaseValue:   m.BaseValue,
			OutputScore: m.OutputScore,
		}
		if expl.Method == "" {
			expl.Method = "SHAP_TreeExplainer"
		}
		for _, rawItem := range m.TopFeatures {
			var item SHAPFeatureItem
			if err := json.Unmarshal(rawItem, &item); err == nil {
				expl.TopFeatures = append(expl.TopFeatures, item)
			}
		}
		return expl
	}

	return nil
}
