package mlingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

// TestAdversarial_MLIngest_CannotBypassPolicy tests that a client cannot bypass high-risk approval
// simply by sending requires_approval: false for credit-scoring-xgboost.
func TestAdversarial_MLIngest_CannotBypassPolicy(t *testing.T) {
	q := ledger.NewBoundedQueue(100, nil)
	rm := registry.NewRegistryManagerWithDefaults()
	store := dualmode.NewMemoryDecisionStore()
	handler := NewIngestHandler(q, rm, store)

	score := 720.5
	payload := MLIngestRequest{
		AISystemID:       "credit-scoring-xgboost",
		ModelVersion:     "v2.1.0",
		ArtifactHash:     "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		Score:            &score,
		Decision:         "APPROVE",
		RequiresApproval: false, // Attempt to bypass approval policy
		Features: map[string]interface{}{
			"income": 50000000,
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ml/ingest", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Must be intercepted (202 Accepted) despite client setting requires_approval: false
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 Accepted due to registry policy override, got %d", rec.Code)
	}

	var interceptResp MLIngestInterceptResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &interceptResp); err != nil {
		t.Fatalf("failed to parse intercept response: %v", err)
	}
	if interceptResp.Status != "PENDING_APPROVAL" || interceptResp.DecisionID == "" {
		t.Fatalf("invalid intercept response content: %+v", interceptResp)
	}
}

// TestAdversarial_MLIngest_ConcurrentLoad tests ML Ingest handler under high concurrent request volume for audit-only system.
func TestAdversarial_MLIngest_ConcurrentLoad(t *testing.T) {
	q := ledger.NewBoundedQueue(1000, nil)
	rm := registry.NewRegistryManagerWithDefaults()
	store := dualmode.NewMemoryDecisionStore()
	handler := NewIngestHandler(q, rm, store)

	numRequests := 100
	var wg sync.WaitGroup
	wg.Add(numRequests)

	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numRequests; i++ {
		reqIdx := i
		go func() {
			defer wg.Done()
			score := 720.5
			payload := MLIngestRequest{
				AISystemID:       "securities-quant-advisor-v1",
				ModelVersion:     "v1.0",
				Score:            &score,
				Decision:         "HOLD",
				Features: map[string]interface{}{
					"applicant_note": fmt.Sprintf("Khách hàng %d có CCCD 001090012345 và STK: 19034567890123", reqIdx),
					"income":         50000000,
				},
				RequiresApproval: false, // Audit-only
			}

			bodyBytes, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ml/ingest", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				mu.Lock()
				successCount++
				mu.Unlock()
			} else {
				t.Errorf("request %d failed with code %d: %s", reqIdx, rec.Code, rec.Body.String())
			}
		}()
	}

	wg.Wait()

	if successCount != numRequests {
		t.Fatalf("expected %d successful requests, got %d", numRequests, successCount)
	}
}

// TestAdversarial_MLIngest_MalformedPayloads tests resilience against malformed inputs and hostile injections.
func TestAdversarial_MLIngest_MalformedPayloads(t *testing.T) {
	q := ledger.NewBoundedQueue(100, nil)
	rm := registry.NewRegistryManagerWithDefaults()
	store := dualmode.NewMemoryDecisionStore()
	handler := NewIngestHandler(q, rm, store)

	attacks := []struct {
		name           string
		body           string
		expectedStatus int
	}{
		{"EmptyBody", "", http.StatusBadRequest},
		{"TruncatedJSON", `{"ai_system_id": "credit-scoring-xgboost", "score":`, http.StatusBadRequest},
		{"InvalidJSONType_ScoreAsString", `{"ai_system_id": "credit-scoring-xgboost", "score": "seven_hundred"}`, http.StatusBadRequest},
		{"MissingAISystemID", `{"score": 750.0}`, http.StatusBadRequest},
		{"ShadowAISystem", `{"ai_system_id": "unregistered-ml-model", "score": 750.0}`, http.StatusForbidden},
		{"TamperedArtifactHash", `{"ai_system_id": "credit-scoring-xgboost", "score": 750.0, "artifact_hash": "bad-hash"}`, http.StatusForbidden},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ml/ingest", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Fatalf("[%s] expected status %d, got %d (body: %s)", tc.name, tc.expectedStatus, rec.Code, rec.Body.String())
			}
		})
	}
}
