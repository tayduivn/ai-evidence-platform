package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/fourofeyes"
	"ei-evidence-platform/services/approval/internal/lifecycle"
	"ei-evidence-platform/services/approval/internal/signer"
	"ei-evidence-platform/services/ledger"
)

type mockGatewayStore struct {
	statuses map[string]string
}

func (m *mockGatewayStore) UpdateStatus(id string, status string) error {
	m.statuses[id] = status
	return nil
}

func setupTestAPI() (*Service, http.Handler, *mockGatewayStore, *ledger.BoundedQueue) {
	approvalStore := lifecycle.NewMemoryApprovalStore()
	fourEyes := fourofeyes.NewEngine()
	dwellEngine := dwell.NewEngine()
	signerRegistry := signer.NewRegistry()

	internalSigner, _ := signer.NewInternalSigner(signer.InternalSignerConfig{
		ApproverID: "test-approver",
	})
	tokenSigner, _ := signer.NewCAVNTokenSigner(signer.CAVNTokenConfig{
		ApproverName: "Nguyen Van Dac",
	})
	signerRegistry.Register(internalSigner)
	signerRegistry.Register(tokenSigner)

	sm := lifecycle.NewApprovalStateMachine(approvalStore, fourEyes, dwellEngine, signerRegistry)

	gatewayStore := &mockGatewayStore{statuses: make(map[string]string)}
	ledgerQueue := ledger.NewBoundedQueue(100, nil)

	service := NewService(sm, gatewayStore, ledgerQueue)
	router := NewRouter(service, nil)

	return service, router, gatewayStore, ledgerQueue
}

func TestAPI_HealthAndReady(t *testing.T) {
	_, router, _, _ := setupTestAPI()

	// GET /health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// GET /ready
	req = httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAPI_PendingListAndGetDetail(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	score := 785.5
	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-ml-882194",
		CorrelationID:   "cust-app-99812",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		ModelVersion:    "v2.1.0",
		CreatorID:       "loan-officer-originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
		Score:           &score,
		Decision:        "APPROVE_LOAN_500M",
		Payload: map[string]interface{}{
			"monthly_income": 45000000,
			"debt_ratio":     0.28,
		},
		CreatedAt: time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	// 1. GET /api/v1/approvals/pending
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/pending", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("pending list failed with %d: %s", rr.Code, rr.Body.String())
	}

	var pendingResp PendingApprovalsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &pendingResp)
	if pendingResp.TotalCount != 1 || len(pendingResp.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", pendingResp.TotalCount)
	}
	if pendingResp.Items[0].DecisionID != "dec-ml-882194" {
		t.Errorf("expected dec-ml-882194, got %s", pendingResp.Items[0].DecisionID)
	}

	// 2. GET /api/v1/approvals/{id}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/approvals/dec-ml-882194", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail failed with %d", rr.Code)
	}

	var detail ApprovalDetail
	_ = json.Unmarshal(rr.Body.Bytes(), &detail)
	if detail.DecisionID != "dec-ml-882194" || detail.MLContext == nil || detail.MLContext.Score != 785.5 {
		t.Errorf("invalid detail structure: %+v", detail)
	}

	// 3. GET /api/v1/approvals/{unknown} -> 404
	req = httptest.NewRequest(http.MethodGet, "/api/v1/approvals/unknown-id", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestAPI_DwellHeartbeat(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-dwell-1",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		MinDwellSeconds: 10,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	body, _ := json.Marshal(DwellHeartbeatRequest{
		ViewerID:      "credit-lead",
		SessionID:     "sess-01",
		IncrementalMs: 2000,
		TabFocused:    true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-dwell-1/dwell", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("dwell heartbeat failed: %d", rr.Code)
	}

	var resp DwellHeartbeatResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.AccumulatedDwellMs != 2000 || resp.RemainingSeconds != 8 || resp.DwellMet != false {
		t.Errorf("unexpected dwell response: %+v", resp)
	}
}

func TestAPI_DecideFull4EyesWorkflow(t *testing.T) {
	service, router, gatewayStore, ledgerQueue := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-fintech-500m",
		CorrelationID:   "tx-corr-992",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		ModelVersion:    "v2.1.0",
		CreatorID:       "loan-officer-originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	// Also record initial status in mock Gateway Store
	gatewayStore.statuses[rec.DecisionID] = "PENDING"

	// 1. Creator self-approval -> 403 CREATOR_CANNOT_APPROVE
	body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "loan-officer-originator",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-fintech-500m/decide", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// 2. Dwell time < 10s -> 422 DWELL_TIME_NOT_MET
	body, _ = json.Marshal(DecideActionRequest{
		ApproverID:   "approver-01",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 5,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-fintech-500m/decide", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}

	// 3. Approver 1 approves -> 200 AWAITING_SECOND_APPROVAL
	body, _ = json.Marshal(DecideActionRequest{
		ApproverID:   "credit-lead-01",
		Role:         "credit_lead",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SignerType:   "internal",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-fintech-500m/decide", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var decideResp1 DecideActionResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &decideResp1)
	if decideResp1.Status != lifecycle.StatusAwaitingSecondApproval || decideResp1.StepIndex != 1 {
		t.Errorf("expected AWAITING_SECOND_APPROVAL step 1, got %+v", decideResp1)
	}

	// Gateway Store must be updated to AWAITING_SECOND_APPROVAL
	if gatewayStore.statuses["dec-fintech-500m"] != "AWAITING_SECOND_APPROVAL" {
		t.Errorf("expected gateway status AWAITING_SECOND_APPROVAL, got %s", gatewayStore.statuses["dec-fintech-500m"])
	}

	// Ledger Queue must have 1 event
	if ledgerQueue.Len() != 1 {
		t.Errorf("expected 1 event in ledger queue, got %d", ledgerQueue.Len())
	}

	// 4. Duplicate approval by credit-lead-01 -> 400 DUPLICATE_APPROVER
	req = httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-fintech-500m/decide", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	// 5. Approver 2 approves with ca_vn_token -> 200 APPROVED
	body, _ = json.Marshal(DecideActionRequest{
		ApproverID:   "cro-risk-officer-02",
		Role:         "risk_officer",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 20,
		SignerType:   "ca_vn_token",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-fintech-500m/decide", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var decideResp2 DecideActionResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &decideResp2)
	if decideResp2.Status != lifecycle.StatusApproved || decideResp2.StepIndex != 2 {
		t.Errorf("expected APPROVED step 2, got %+v", decideResp2)
	}

	// Gateway Store must be updated to APPROVED
	if gatewayStore.statuses["dec-fintech-500m"] != "APPROVED" {
		t.Errorf("expected gateway status APPROVED, got %s", gatewayStore.statuses["dec-fintech-500m"])
	}

	// Ledger Queue must now have 2 events
	if ledgerQueue.Len() != 2 {
		t.Errorf("expected 2 events in ledger queue, got %d", ledgerQueue.Len())
	}
}

func TestAPI_DecideRejection(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-reject-api",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		MinDwellSeconds: 10,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "risk-reviewer",
		Action:       lifecycle.ActionReject,
		DwellSeconds: 12,
		Comment:      "High fraud probability",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-reject-api/decide", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp DecideActionResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != lifecycle.StatusRejected {
		t.Errorf("expected REJECTED, got %s", resp.Status)
	}
}

func TestAPI_WebUIDecideWithSessionTokenAndDynamicDwell(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-web-ui-session",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 15,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	sessionID := "web-session-active"

	// 1. Attempt to decide without heartbeats -> Must fail with 422
	bodyFail, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "approver-web",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SessionToken: sessionID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-web-ui-session/decide", bytes.NewReader(bodyFail))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for unrecorded session heartbeats, got %d: %s", rr.Code, rr.Body.String())
	}

	// 2. Send heartbeats to accumulate 16 seconds (8 x 2000ms = 16s)
	for i := 0; i < 8; i++ {
		hbBody, _ := json.Marshal(DwellHeartbeatRequest{
			ViewerID:      "approver-web",
			SessionID:     sessionID,
			IncrementalMs: 2000,
			TabFocused:    true,
		})
		hbReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-web-ui-session/dwell", bytes.NewReader(hbBody))
		hbRR := httptest.NewRecorder()
		router.ServeHTTP(hbRR, hbReq)
		if hbRR.Code != http.StatusOK {
			t.Fatalf("heartbeat %d failed: %d", i, hbRR.Code)
		}
	}

	// 3. Now submit decide with session token and dynamic dwell (16s >= 15s) -> Must succeed 200 OK
	bodySuccess, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "approver-web",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 16,
		SessionToken: sessionID,
		SignerType:   "internal",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-web-ui-session/decide", bytes.NewReader(bodySuccess))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid session dwell, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp DecideActionResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != lifecycle.StatusApproved {
		t.Errorf("expected APPROVED, got %s", resp.Status)
	}
}

func TestAPI_UnregisteredSignerType_Returns400(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-unreg-api",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "approver-web",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SignerType:   "unregistered-signer-type",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-unreg-api/decide", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered signer, got %d: %s", rr.Code, rr.Body.String())
	}

	var errMap map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &errMap)
	if errMap["code"] != "SIGNER_NOT_FOUND" {
		t.Errorf("expected SIGNER_NOT_FOUND code, got %v", errMap["code"])
	}
}

