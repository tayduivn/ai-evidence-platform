package mlingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

func TestMLIngest_ValidAuditOnly(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	store := dualmode.NewMemoryDecisionStore()
	h := NewIngestHandler(queue, rm, store)

	score := 650.0
	reqBody := MLIngestRequest{
		AISystemID:       "securities-quant-advisor-v1",
		ModelVersion:     "v1.0",
		Score:            &score,
		Decision:         "HOLD",
		RequiresApproval: false,
		Features: map[string]interface{}{
			"volatility": 0.15,
		},
		CorrelationID: "tx-test-ml-audit-01",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MLIngestSuccessResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "INGESTED" || resp.CorrelationID != "tx-test-ml-audit-01" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	select {
	case event := <-queue.Events():
		if event.EventType != ledger.EventTypeMLDecision || event.Status != "COMPLETED" {
			t.Fatalf("unexpected queued event: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for audit event")
	}
}

func TestMLIngest_ValidIntercept(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	store := dualmode.NewMemoryDecisionStore()
	h := NewIngestHandler(queue, rm, store)

	score := 785.5
	reqBody := MLIngestRequest{
		AISystemID:   "credit-scoring-xgboost",
		ModelVersion: "v2.1.0",
		ArtifactHash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		Features: map[string]interface{}{
			"income": 45000000,
		},
		Score:            &score,
		Decision:         "APPROVE_LOAN_500M",
		CorrelationID:    "tx-fintech-loan-88912",
		RequiresApproval: true,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/api/v1/decisions/dec-ml-") {
		t.Fatalf("unexpected Location header: %s", location)
	}

	var resp MLIngestInterceptResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "PENDING_APPROVAL" || !strings.HasPrefix(resp.DecisionID, "dec-ml-") {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// Verify in store
	recInStore, err := store.Get(resp.DecisionID)
	if err != nil || recInStore.Status != dualmode.StatusPending {
		t.Fatalf("record not properly persisted in store: %v", recInStore)
	}
}

func TestMLIngest_MissingAISystemID(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	h := NewIngestHandler(nil, rm, nil)

	score := 700.0
	reqBody := MLIngestRequest{
		Score: &score,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Missing required field: ai_system_id") {
		t.Fatalf("unexpected error message: %s", rec.Body.String())
	}
}

func TestMLIngest_MissingScore(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	h := NewIngestHandler(nil, rm, nil)

	reqBody := MLIngestRequest{
		AISystemID: "credit-scoring-xgboost",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Missing required field: score") {
		t.Fatalf("unexpected error message: %s", rec.Body.String())
	}
}

func TestMLIngest_ShadowAI_Unregistered(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	h := NewIngestHandler(nil, rm, nil)

	score := 700.0
	reqBody := MLIngestRequest{
		AISystemID: "unregistered-ml-model",
		Score:      &score,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Shadow AI rejected") {
		t.Fatalf("unexpected error message: %s", rec.Body.String())
	}
}

func TestMLIngest_ArtifactHashMismatch(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	h := NewIngestHandler(nil, rm, nil)

	score := 700.0
	reqBody := MLIngestRequest{
		AISystemID:   "credit-scoring-xgboost",
		ArtifactHash: "tampered_artifact_hash_123456",
		Score:        &score,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Artifact hash mismatch") {
		t.Fatalf("unexpected error message: %s", rec.Body.String())
	}
}

func TestMLIngest_PIIScanningAndMasking(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	store := dualmode.NewMemoryDecisionStore()
	h := NewIngestHandler(queue, rm, store)

	score := 785.5
	reqBody := MLIngestRequest{
		AISystemID:   "credit-scoring-xgboost",
		ModelVersion: "v2.1.0",
		ArtifactHash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		Features: map[string]interface{}{
			"cccd":  "001090012345",
			"phone": "0912345678",
			"notes": "STK: 19034567890123 VCB",
		},
		Score:            &score,
		RequiresApproval: true,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", rec.Code)
	}

	select {
	case event := <-queue.Events():
		if !event.PIIFlag {
			t.Fatalf("expected PIIFlag = true")
		}
		if len(event.PIIDetected) != 3 {
			t.Fatalf("expected 3 detected PII types, got: %v", event.PIIDetected)
		}
		// Verify masked in payload
		feat := event.Payload
		if feat["cccd"] != "001******345" {
			t.Fatalf("expected masked cccd, got %v", feat["cccd"])
		}
		if feat["phone"] != "091****678" {
			t.Fatalf("expected masked phone, got %v", feat["phone"])
		}
		if !strings.Contains(feat["notes"].(string), "1903******0123") {
			t.Fatalf("expected masked bank account, got %v", feat["notes"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for event")
	}
}

func TestMLIngest_SHAPExplanationFidelity(t *testing.T) {
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	store := dualmode.NewMemoryDecisionStore()
	h := NewIngestHandler(queue, rm, store)

	score := 785.5
	reqBody := MLIngestRequest{
		AISystemID:   "credit-scoring-xgboost",
		ModelVersion: "v2.1.0",
		ArtifactHash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		Score:        &score,
		Explanation: &MLExplanation{
			Method: "SHAP_TreeExplainer",
			TopFeatures: []FeatureImpact{
				{Feature: "income", Importance: 0.42, Contribution: "+65pts"},
				{Feature: "debt_ratio", Importance: 0.31, Contribution: "+40pts"},
			},
		},
		RequiresApproval: true,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/ml/ingest", strings.NewReader(string(bodyBytes)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", rec.Code)
	}

	var resp MLIngestInterceptResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	saved, err := store.Get(resp.DecisionID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved.Explanation == nil {
		t.Fatalf("expected explanation saved in store")
	}
}
