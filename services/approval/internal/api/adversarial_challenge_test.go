package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/lifecycle"
)

// ---------------------------------------------------------------------------
// 1. Creator Self-Approval Bypass Adversarial Tests
// ---------------------------------------------------------------------------

func TestAdversarial_CreatorSelfApprovalBypass(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	creatorID := "loan-officer-creator-99"
	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-creator-bypass",
		CorrelationID:   "tx-adv-001",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       creatorID,
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		RequiredRoles:   []string{"credit_lead", "cro_risk_officer"},
		MinDwellSeconds: 10,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	testCases := []struct {
		name         string
		approverID   string
		role         string
		dwellSeconds int
		action       lifecycle.ApprovalAction
	}{
		{
			name:         "Direct creator approval attempt",
			approverID:   creatorID,
			role:         "credit_lead",
			dwellSeconds: 15,
			action:       lifecycle.ActionApprove,
		},
		{
			name:         "Creator approval with elevated admin role",
			approverID:   creatorID,
			role:         "admin",
			dwellSeconds: 60,
			action:       lifecycle.ActionApprove,
		},
		{
			name:         "Creator approval with empty role",
			approverID:   creatorID,
			role:         "",
			dwellSeconds: 30,
			action:       lifecycle.ActionApprove,
		},
		{
			name:         "Creator reject attempt",
			approverID:   creatorID,
			role:         "credit_lead",
			dwellSeconds: 15,
			action:       lifecycle.ActionReject,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   tc.approverID,
				Role:         tc.role,
				Action:       tc.action,
				DwellSeconds: tc.dwellSeconds,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-creator-bypass/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("[%s] expected HTTP 403 Forbidden, got %d: %s", tc.name, rr.Code, rr.Body.String())
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("failed to decode error JSON: %v", err)
			}

			if errResp.Code != "CREATOR_CANNOT_APPROVE" {
				t.Errorf("[%s] expected error code CREATOR_CANNOT_APPROVE, got %s", tc.name, errResp.Code)
			}
			if !strings.Contains(errResp.Error, "CREATOR_CANNOT_APPROVE") {
				t.Errorf("[%s] expected error message containing CREATOR_CANNOT_APPROVE, got %s", tc.name, errResp.Error)
			}
		})
	}

	// Also verify creator cannot approve at Step 2 after legitimate Step 1 approval
	step1Body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "legit-approver-01",
		Role:         "credit_lead",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SignerType:   "internal",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-creator-bypass/decide", bytes.NewReader(step1Body))
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("Step 1 legitimate approval failed: %d", rr1.Code)
	}

	// Now creator tries to approve at Step 2
	step2CreatorBody, _ := json.Marshal(DecideActionRequest{
		ApproverID:   creatorID,
		Role:         "cro_risk_officer",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 20,
		SignerType:   "internal",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-creator-bypass/decide", bytes.NewReader(step2CreatorBody))
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusForbidden {
		t.Fatalf("Creator approval at Step 2 expected HTTP 403, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var errResp2 ErrorResponse
	_ = json.Unmarshal(rr2.Body.Bytes(), &errResp2)
	if errResp2.Code != "CREATOR_CANNOT_APPROVE" {
		t.Errorf("Step 2 creator bypass expected code CREATOR_CANNOT_APPROVE, got %s", errResp2.Code)
	}
}

// ---------------------------------------------------------------------------
// 2. Rapid Double-Click Race Condition (Same Approver Concurrency)
// ---------------------------------------------------------------------------

func TestAdversarial_RapidDoubleClickRaceCondition(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-double-click-race",
		CorrelationID:   "tx-adv-race-002",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       "originator-user",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		RequiredRoles:   []string{"credit_lead", "cro_risk_officer"},
		MinDwellSeconds: 10,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	const concurrencyCount = 20
	var wg sync.WaitGroup
	var successCount int32
	var duplicateApproverCount int32
	var otherErrorCount int32

	for i := 0; i < concurrencyCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   "same-approver-doubleclick",
				Role:         "credit_lead",
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 15,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-double-click-race/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			} else if rr.Code == http.StatusBadRequest {
				var errResp ErrorResponse
				_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
				if errResp.Code == "DUPLICATE_APPROVER" {
					atomic.AddInt32(&duplicateApproverCount, 1)
				} else {
					atomic.AddInt32(&otherErrorCount, 1)
				}
			} else {
				atomic.AddInt32(&otherErrorCount, 1)
			}
		}(i)
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("CRITICAL RACE CONDITION FAILURE: Expected exactly 1 successful approval, got %d", successCount)
	}
	if duplicateApproverCount != concurrencyCount-1 {
		t.Fatalf("Expected %d DUPLICATE_APPROVER rejections, got %d (other errors: %d)", concurrencyCount-1, duplicateApproverCount, otherErrorCount)
	}

	// Verify state store consistency
	saved, _ := service.StateMachine.GetStore().Get("dec-adv-double-click-race")
	if saved.Status != lifecycle.StatusAwaitingSecondApproval {
		t.Errorf("Expected status AWAITING_SECOND_APPROVAL, got %s", saved.Status)
	}
	if len(saved.Approvals) != 1 {
		t.Errorf("Expected exactly 1 approval recorded, got %d", len(saved.Approvals))
	}

	// Now perform second step race with a second distinct approver
	var successCountStep2 int32
	var duplicateApproverStep2 int32
	var otherErrorStep2 int32

	for i := 0; i < concurrencyCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   "second-approver-doubleclick",
				Role:         "cro_risk_officer",
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 20,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-double-click-race/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				atomic.AddInt32(&successCountStep2, 1)
			} else if rr.Code == http.StatusBadRequest {
				var errResp ErrorResponse
				_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
				if errResp.Code == "DUPLICATE_APPROVER" || errResp.Code == "TERMINAL_STATE" {
					atomic.AddInt32(&duplicateApproverStep2, 1)
				} else {
					atomic.AddInt32(&otherErrorStep2, 1)
				}
			} else {
				atomic.AddInt32(&otherErrorStep2, 1)
			}
		}(i)
	}
	wg.Wait()

	if successCountStep2 != 1 {
		t.Fatalf("Step 2 Race: Expected exactly 1 approval, got %d", successCountStep2)
	}
	if duplicateApproverStep2 != concurrencyCount-1 {
		t.Errorf("Step 2 Race: Expected %d rejections, got %d", concurrencyCount-1, duplicateApproverStep2)
	}

	savedFinal, _ := service.StateMachine.GetStore().Get("dec-adv-double-click-race")
	if savedFinal.Status != lifecycle.StatusApproved {
		t.Errorf("Expected final status APPROVED, got %s", savedFinal.Status)
	}
	if len(savedFinal.Approvals) != 2 {
		t.Errorf("Expected exactly 2 approvals, got %d", len(savedFinal.Approvals))
	}
}

// ---------------------------------------------------------------------------
// 3. Unprivileged Role Approval Attempts
// ---------------------------------------------------------------------------

func TestAdversarial_UnprivilegedRoleApproval(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-role-hierarchy",
		CorrelationID:   "tx-adv-role-003",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       "originator-1",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		RequiredRoles:   []string{"credit_lead", "cro_risk_officer"},
		MinDwellSeconds: 10,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	unprivilegedRoles := []string{
		"junior_analyst",
		"intern",
		"teller",
		"customer_service",
		"guest",
		"cro_risk_officer", // wrong sequence (this is step 2 role, not step 1)
	}

	for _, unprivilegedRole := range unprivilegedRoles {
		t.Run("Reject role: "+unprivilegedRole, func(t *testing.T) {
			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   "unprivileged-user-" + unprivilegedRole,
				Role:         unprivilegedRole,
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 15,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-role-hierarchy/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("Expected HTTP 400 for unprivileged role %s, got %d: %s", unprivilegedRole, rr.Code, rr.Body.String())
			}

			var errResp ErrorResponse
			_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
			if errResp.Code != "VALIDATION_FAILED" {
				t.Errorf("Expected code VALIDATION_FAILED, got %s", errResp.Code)
			}
			if !strings.Contains(errResp.Error, "ROLE_MISMATCH") {
				t.Errorf("Expected error containing ROLE_MISMATCH, got: %s", errResp.Error)
			}
		})
	}

	// Step 1: Legitimate credit_lead succeeds
	step1Body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "qualified-credit-lead",
		Role:         "credit_lead",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SignerType:   "internal",
	})
	reqStep1 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-role-hierarchy/decide", bytes.NewReader(step1Body))
	rrStep1 := httptest.NewRecorder()
	router.ServeHTTP(rrStep1, reqStep1)
	if rrStep1.Code != http.StatusOK {
		t.Fatalf("Legitimate step 1 approval failed: %d: %s", rrStep1.Code, rrStep1.Body.String())
	}

	// Step 2: Now test wrong roles for step 2 (e.g. credit_lead trying to do step 2)
	wrongStep2Roles := []string{"credit_lead", "junior_analyst", "branch_manager"}
	for _, wrongRole := range wrongStep2Roles {
		t.Run("Step 2 reject wrong role: "+wrongRole, func(t *testing.T) {
			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   "user-step2-" + wrongRole,
				Role:         wrongRole,
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 20,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-role-hierarchy/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("Step 2 expected HTTP 400 for wrong role %s, got %d: %s", wrongRole, rr.Code, rr.Body.String())
			}
		})
	}

	// Step 2: Legitimate cro_risk_officer succeeds
	step2Body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "qualified-cro-officer",
		Role:         "cro_risk_officer",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 20,
		SignerType:   "internal",
	})
	reqStep2 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-role-hierarchy/decide", bytes.NewReader(step2Body))
	rrStep2 := httptest.NewRecorder()
	router.ServeHTTP(rrStep2, reqStep2)
	if rrStep2.Code != http.StatusOK {
		t.Fatalf("Legitimate step 2 approval failed: %d: %s", rrStep2.Code, rrStep2.Body.String())
	}
}

func TestAdversarial_EmptyRoleWithRequiredRoles(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-empty-role",
		CorrelationID:   "tx-adv-empty-role",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       "originator-1",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		RequiredRoles:   []string{"credit_lead", "cro_risk_officer"},
		MinDwellSeconds: 10,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	// Attempt approval with EMPTY role when RequiredRoles is specified
	body, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "anonymous-role-user",
		Role:         "", // EMPTY ROLE!
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15,
		SignerType:   "internal",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-empty-role/decide", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	t.Logf("Response code for empty role when RequiredRoles set: %d, body: %s", rr.Code, rr.Body.String())
}

// ---------------------------------------------------------------------------
// 4. Anti-Rubberstamping Dwell Time Boundary Tests
// ---------------------------------------------------------------------------

func TestAdversarial_DwellTimeBoundaries(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	createDecision := func(id string, minDwell int) {
		rec := &lifecycle.ApprovalDecisionRecord{
			DecisionID:      id,
			CorrelationID:   "tx-" + id,
			AISystemID:      "credit-scoring-xgboost",
			SystemType:      "ml",
			CreatorID:       "originator-1",
			Status:          lifecycle.StatusPending,
			Requires4Eyes:   false,
			MinDwellSeconds: minDwell,
			CreatedAt:       time.Now().UTC(),
		}
		_ = service.StateMachine.GetStore().Save(rec)
	}

	// Sub-test 1: Exactly 1s below threshold -> HTTP 422 DWELL_TIME_NOT_MET
	t.Run("Dwell exactly 1s below threshold (9s < 10s)", func(t *testing.T) {
		decID := "dec-dwell-sub-1"
		createDecision(decID, 10)

		body, _ := json.Marshal(DecideActionRequest{
			ApproverID:   "approver-sub1",
			Action:       lifecycle.ActionApprove,
			DwellSeconds: 9, // Exactly 1s below 10s
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("Expected HTTP 422 for 9s dwell, got %d: %s", rr.Code, rr.Body.String())
		}

		var errResp ErrorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
		if errResp.Code != "DWELL_TIME_NOT_MET" {
			t.Errorf("Expected code DWELL_TIME_NOT_MET, got %s", errResp.Code)
		}
		if !strings.Contains(errResp.Error, "DWELL_TIME_NOT_MET") {
			t.Errorf("Expected message containing DWELL_TIME_NOT_MET, got %s", errResp.Error)
		}
		reqSec, ok1 := errResp.Details["required_seconds"].(float64)
		elSec, ok2 := errResp.Details["elapsed_seconds"].(float64)
		if !ok1 || !ok2 || reqSec != 10 || elSec != 9 {
			t.Errorf("Unexpected details in 422 response: %+v", errResp.Details)
		}
	})

	// Sub-test 2: Zero second rubberstamp -> HTTP 422
	t.Run("Dwell zero second rubberstamp (0s < 10s)", func(t *testing.T) {
		decID := "dec-dwell-zero"
		createDecision(decID, 10)

		body, _ := json.Marshal(DecideActionRequest{
			ApproverID:   "approver-zero",
			Action:       lifecycle.ActionApprove,
			DwellSeconds: 0,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("Expected HTTP 422 for 0s dwell, got %d", rr.Code)
		}
	})

	// Sub-test 3: Exactly at threshold -> HTTP 200 OK
	t.Run("Dwell exactly at threshold (10s == 10s)", func(t *testing.T) {
		decID := "dec-dwell-exact"
		createDecision(decID, 10)

		body, _ := json.Marshal(DecideActionRequest{
			ApproverID:   "approver-exact",
			Action:       lifecycle.ActionApprove,
			DwellSeconds: 10, // Exactly at 10s
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected HTTP 200 for exact threshold dwell (10s), got %d: %s", rr.Code, rr.Body.String())
		}
	})

	// Sub-test 4: 1s above threshold -> HTTP 200 OK
	t.Run("Dwell 1s above threshold (11s > 10s)", func(t *testing.T) {
		decID := "dec-dwell-above"
		createDecision(decID, 10)

		body, _ := json.Marshal(DecideActionRequest{
			ApproverID:   "approver-above",
			Action:       lifecycle.ActionApprove,
			DwellSeconds: 11,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected HTTP 200 for 11s dwell, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	// Sub-test 5: Session Token cross-verification (spoofed submitted time with low heartbeat)
	t.Run("Session Token cross-verification rejects spoofed submitted dwell", func(t *testing.T) {
		decID := "dec-dwell-session-cross"
		createDecision(decID, 10)

		sessionID := "sess-cross-verify-1"
		// Send heartbeat totaling 8,000ms (8 seconds)
		_, _, _, _ = service.StateMachine.GetDwellEngine().RecordHeartbeat(sessionID, decID, "approver-spoof", 3000, true)
		_, _, _, _ = service.StateMachine.GetDwellEngine().RecordHeartbeat(sessionID, decID, "approver-spoof", 3000, true)
		_, _, _, _ = service.StateMachine.GetDwellEngine().RecordHeartbeat(sessionID, decID, "approver-spoof", 2000, true)

		// Client claims DwellSeconds = 25s, but passes session token with only 8s
		body, _ := json.Marshal(DecideActionRequest{
			ApproverID:   "approver-spoof",
			Action:       lifecycle.ActionApprove,
			DwellSeconds: 25, // Lies about duration
			SessionToken: sessionID,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("Expected HTTP 422 when cross-verifying session token, got %d: %s", rr.Code, rr.Body.String())
		}

		// Now add 2,000ms more to reach 10s
		_, _, _, _ = service.StateMachine.GetDwellEngine().RecordHeartbeat(sessionID, decID, "approver-spoof", 2000, true)

		// Submit again with session token
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+decID+"/decide", bytes.NewReader(body))
		rr2 := httptest.NewRecorder()
		router.ServeHTTP(rr2, req2)

		if rr2.Code != http.StatusOK {
			t.Fatalf("Expected HTTP 200 after session reached 10s, got %d: %s", rr2.Code, rr2.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// 5. Artificial Tick Clamping & Heartbeat Spoofing
// ---------------------------------------------------------------------------

func TestAdversarial_TickClampingAndHeartbeatSpoofing(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-tick-clamping",
		CorrelationID:   "tx-adv-clamping-005",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       "originator-1",
		Status:          lifecycle.StatusPending,
		MinDwellSeconds: 30,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	sessID := "sess-spoof-tick-test"

	// 1. Send single massive 100-second tick (100,000 ms) via REST API
	heartbeatBody, _ := json.Marshal(DwellHeartbeatRequest{
		ViewerID:      "viewer-attacker",
		SessionID:     sessID,
		IncrementalMs: 100000, // 100s spoof attempt
		TabFocused:    true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-tick-clamping/dwell", bytes.NewReader(heartbeatBody))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Heartbeat endpoint failed: %d", rr.Code)
	}

	var resp DwellHeartbeatResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// MUST be clamped to <= 3000ms!
	if resp.AccumulatedDwellMs > 3000 {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: 100s tick was not clamped! Got %d ms (expected <= 3000ms)", resp.AccumulatedDwellMs)
	}
	if resp.AccumulatedDwellMs != 3000 {
		t.Errorf("Expected exactly 3000ms clamped tick, got %d", resp.AccumulatedDwellMs)
	}
	if resp.RemainingSeconds != 27 { // 30 - 3 = 27
		t.Errorf("Expected remaining 27s, got %d", resp.RemainingSeconds)
	}
	if resp.DwellMet != false {
		t.Errorf("Expected DwellMet to be false, got true")
	}

	// 2. Direct Engine Clamping Verification
	dwellEng := dwell.NewEngine()

	// Spoof with 1,000,000 ms
	accum1, _, _, err := dwellEng.RecordHeartbeat("direct-sess", "dec-1", "user-1", 1000000, true)
	if err != nil {
		t.Fatalf("RecordHeartbeat error: %v", err)
	}
	if accum1 > 3000 {
		t.Errorf("Direct engine failed clamping 1,000,000ms tick: got %d", accum1)
	}

	// Send negative tick (-5000 ms)
	accum2, _, _, _ := dwellEng.RecordHeartbeat("direct-sess", "dec-1", "user-1", -5000, true)
	if accum2 != accum1 {
		t.Errorf("Negative tick altered accumulated time: before %d, after %d", accum1, accum2)
	}

	// Send tab unfocused tick (tabFocused = false, 3000 ms)
	accum3, _, _, _ := dwellEng.RecordHeartbeat("direct-sess", "dec-1", "user-1", 3000, false)
	if accum3 != accum1 {
		t.Errorf("Unfocused tab incremented accumulated time: before %d, after %d", accum1, accum3)
	}

	// Normal valid tick (2500 ms)
	accum4, _, _, _ := dwellEng.RecordHeartbeat("direct-sess", "dec-1", "user-1", 2500, true)
	expected := accum1 + 2500
	if accum4 != expected {
		t.Errorf("Valid tick accumulation wrong: expected %d, got %d", expected, accum4)
	}
}

// ---------------------------------------------------------------------------
// 6. Adversarial Attack on Optimistic Concurrency Locking
// ---------------------------------------------------------------------------

func TestAdversarial_OptimisticLockingConflict(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-adv-version-lock",
		CorrelationID:   "tx-adv-ver-006",
		AISystemID:      "credit-scoring-xgboost",
		SystemType:      "ml",
		CreatorID:       "originator-1",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   true,
		RequiredRoles:   []string{"credit_lead", "cro_risk_officer"},
		MinDwellSeconds: 10,
		Version:         1,
		CreatedAt:       time.Now().UTC(),
	}
	_ = service.StateMachine.GetStore().Save(rec)

	// Approver 1 submits with expected_version = 1
	body1, _ := json.Marshal(DecideActionRequest{
		ApproverID:      "approver-ver-1",
		Role:            "credit_lead",
		Action:          lifecycle.ActionApprove,
		DwellSeconds:    15,
		SignerType:      "internal",
		ExpectedVersion: 1,
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-version-lock/decide", bytes.NewReader(body1))
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("Version 1 approval failed: %d", rr1.Code)
	}

	// Now record has version 2. Approver 2 tries to submit with stale expected_version = 1
	bodyStale, _ := json.Marshal(DecideActionRequest{
		ApproverID:      "approver-ver-2",
		Role:            "cro_risk_officer",
		Action:          lifecycle.ActionApprove,
		DwellSeconds:    15,
		SignerType:      "internal",
		ExpectedVersion: 1, // Stale!
	})
	reqStale := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-adv-version-lock/decide", bytes.NewReader(bodyStale))
	rrStale := httptest.NewRecorder()
	router.ServeHTTP(rrStale, reqStale)

	if rrStale.Code != http.StatusConflict {
		t.Fatalf("Expected HTTP 409 Conflict for stale version, got %d: %s", rrStale.Code, rrStale.Body.String())
	}

	var errResp ErrorResponse
	_ = json.Unmarshal(rrStale.Body.Bytes(), &errResp)
	if errResp.Code != "CONCURRENT_MODIFICATION" {
		t.Errorf("Expected code CONCURRENT_MODIFICATION, got %s", errResp.Code)
	}
}
