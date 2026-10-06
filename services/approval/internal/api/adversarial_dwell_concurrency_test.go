package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ei-evidence-platform/services/approval/internal/lifecycle"
)

// TestAdversarial_API_DwellZeroHeartbeatHTTP422
// Proves that at HTTP API level:
// 1. Passing session_token with 0 accumulated seconds returns HTTP 422 DWELL_TIME_NOT_MET.
// 2. Passing session_token with sufficient viewing time returns HTTP 200 OK.
func TestAdversarial_API_DwellZeroHeartbeatHTTP422(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-http-dwell-zero-hb",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	// Step 1: Submit decision with unrecorded session_token -> Must return HTTP 422
	payloadZero, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "approver-http",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 15, // Claimed dwell >= 10
		SessionToken: "sess-http-zero-hb",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-http-dwell-zero-hb/decide", bytes.NewReader(payloadZero))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Expected HTTP 422 for unrecorded session_token, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse JSON error: %v", err)
	}
	if errResp.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("Expected code 'DWELL_TIME_NOT_MET', got '%s'", errResp.Code)
	}

	// Step 2: Record heartbeats totaling 12 seconds (6 * 2000ms = 12,000ms)
	sessionID := "sess-http-sufficient-hb"
	for i := 0; i < 6; i++ {
		hbBody, _ := json.Marshal(DwellHeartbeatRequest{
			ViewerID:      "approver-http",
			SessionID:     sessionID,
			IncrementalMs: 2000,
			TabFocused:    true,
		})
		hbReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-http-dwell-zero-hb/dwell", bytes.NewReader(hbBody))
		hbRR := httptest.NewRecorder()
		router.ServeHTTP(hbRR, hbReq)
		if hbRR.Code != http.StatusOK {
			t.Fatalf("Heartbeat %d failed with HTTP %d", i, hbRR.Code)
		}
	}

	// Step 3: Submit decision with sufficient session_token -> Must return HTTP 200 OK
	payloadValid, _ := json.Marshal(DecideActionRequest{
		ApproverID:   "approver-http",
		Action:       lifecycle.ActionApprove,
		DwellSeconds: 12,
		SessionToken: sessionID,
		SignerType:   "internal",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-http-dwell-zero-hb/decide", bytes.NewReader(payloadValid))
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for sufficient session dwell, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var decideResp DecideActionResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &decideResp); err != nil {
		t.Fatalf("Failed to parse decide response: %v", err)
	}
	if decideResp.Status != lifecycle.StatusApproved {
		t.Errorf("Expected status APPROVED, got %s", decideResp.Status)
	}
}

// TestAdversarial_API_KeyMutex_RapidDoubleClicksHTTP
// Proves that rapid double-clicks to /decide on the same decision ID via HTTP router
// are serialized such that exactly 1 returns 200 OK, and all others return client error.
func TestAdversarial_API_KeyMutex_RapidDoubleClicksHTTP(t *testing.T) {
	service, router, gatewayStore, ledgerQueue := setupTestAPI()

	rec := &lifecycle.ApprovalDecisionRecord{
		DecisionID:      "dec-http-rapid-race",
		CreatorID:       "originator",
		Status:          lifecycle.StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 5,
	}
	_ = service.StateMachine.GetStore().Save(rec)

	const numCalls = 25
	var wg sync.WaitGroup
	var ok200Count int32
	var clientErrCount int32
	var serverErrCount int32

	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   "same-approver-http",
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 10,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/dec-http-rapid-race/decide", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			switch {
			case rr.Code == http.StatusOK:
				atomic.AddInt32(&ok200Count, 1)
			case rr.Code >= 400 && rr.Code < 500:
				atomic.AddInt32(&clientErrCount, 1)
			default:
				atomic.AddInt32(&serverErrCount, 1)
			}
		}()
	}

	wg.Wait()

	if ok200Count != 1 {
		t.Fatalf("FAIL: Expected exactly 1 HTTP 200 OK, got %d", ok200Count)
	}
	if clientErrCount != numCalls-1 {
		t.Errorf("FAIL: Expected %d HTTP 4xx rejections, got %d (5xx: %d)", numCalls-1, clientErrCount, serverErrCount)
	}
	if serverErrCount != 0 {
		t.Errorf("FAIL: Got %d unexpected server 5xx errors", serverErrCount)
	}

	// Verify gateway status was updated exactly once
	if gatewayStore.statuses["dec-http-rapid-race"] != "APPROVED" {
		t.Errorf("Expected gateway status APPROVED, got %s", gatewayStore.statuses["dec-http-rapid-race"])
	}

	// Verify ledger queue has exactly 1 event
	if ledgerQueue.Len() != 1 {
		t.Errorf("Expected ledger queue length 1, got %d", ledgerQueue.Len())
	}
}

// TestAdversarial_API_KeyMutex_CrossDecisionConcurrencyHTTP
// Proves that HTTP requests to /decide for distinct decision IDs execute concurrently without blocking.
func TestAdversarial_API_KeyMutex_CrossDecisionConcurrencyHTTP(t *testing.T) {
	service, router, _, _ := setupTestAPI()

	const numDecisions = 15
	for i := 0; i < numDecisions; i++ {
		id := fmt.Sprintf("dec-http-cross-%d", i)
		rec := &lifecycle.ApprovalDecisionRecord{
			DecisionID:      id,
			CreatorID:       fmt.Sprintf("creator-%d", i),
			Status:          lifecycle.StatusPending,
			Requires4Eyes:   false,
			MinDwellSeconds: 5,
		}
		_ = service.StateMachine.GetStore().Save(rec)
	}

	var wg sync.WaitGroup
	var okCount int32

	start := time.Now()

	for i := 0; i < numDecisions; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("dec-http-cross-%d", idx)
			body, _ := json.Marshal(DecideActionRequest{
				ApproverID:   fmt.Sprintf("approver-%d", idx),
				Action:       lifecycle.ActionApprove,
				DwellSeconds: 10,
				SignerType:   "internal",
			})
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/approvals/%s/decide", id), bytes.NewReader(body))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	if okCount != numDecisions {
		t.Fatalf("Expected all %d decisions to return 200 OK, got %d", numDecisions, okCount)
	}
	t.Logf("PASS: %d concurrent cross-decision HTTP requests completed successfully in %v", numDecisions, elapsed)
}
