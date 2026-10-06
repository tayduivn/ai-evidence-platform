package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/fourofeyes"
	"ei-evidence-platform/services/approval/internal/signer"
)

// mockInstrumentedSigner records active in-flight signing operations to detect race conditions.
type mockInstrumentedSigner struct {
	signDelay      time.Duration
	activeSigns    int32
	maxActiveSigns int32
}

func (m *mockInstrumentedSigner) Type() string { return "instrumented" }

func (m *mockInstrumentedSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	curr := atomic.AddInt32(&m.activeSigns, 1)
	for {
		oldMax := atomic.LoadInt32(&m.maxActiveSigns)
		if curr <= oldMax || atomic.CompareAndSwapInt32(&m.maxActiveSigns, oldMax, curr) {
			break
		}
	}

	if m.signDelay > 0 {
		time.Sleep(m.signDelay)
	}

	atomic.AddInt32(&m.activeSigns, -1)
	return []byte("dummy-sig-bytes"), []byte("dummy-cert-pem"), nil
}

func (m *mockInstrumentedSigner) Verify(ctx context.Context, payload, signature, certPEM []byte) (bool, error) {
	return true, nil
}

func (m *mockInstrumentedSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	return [][]byte{[]byte("dummy-cert-pem")}, nil
}

// ---------------------------------------------------------------------------
// 1. KeyMutex Cross-Decision Concurrency Tests
// ---------------------------------------------------------------------------

// TestAdversarial_KeyMutex_CrossDecisionConcurrency_ProvesParallelExecution
// Proves that decisions for different IDs run concurrently without blocking.
// If 10 requests with 80ms signing delay each were blocked sequentially by a global lock,
// total runtime would exceed 800ms. In parallel, runtime completes well below 350ms,
// and time windows overlap.
func TestAdversarial_KeyMutex_CrossDecisionConcurrency_ProvesParallelExecution(t *testing.T) {
	store := NewMemoryApprovalStore()
	fourEyes := fourofeyes.NewEngine()
	dwellEngine := dwell.NewEngine()
	registry := signer.NewRegistry()

	// Slow signer with 80ms delay per signing operation
	mockSigner := &mockInstrumentedSigner{signDelay: 80 * time.Millisecond}
	registry.Register(mockSigner)

	sm := NewApprovalStateMachine(store, fourEyes, dwellEngine, registry)

	const numDecisions = 10
	type timeWindow struct {
		start time.Time
		end   time.Time
	}
	windows := make([]timeWindow, numDecisions)

	// Pre-populate 10 distinct decision records
	for i := 0; i < numDecisions; i++ {
		id := fmt.Sprintf("dec-parallel-%d", i)
		rec := &ApprovalDecisionRecord{
			DecisionID:      id,
			CreatorID:       fmt.Sprintf("creator-%d", i),
			Status:          StatusPending,
			Requires4Eyes:   false,
			MinDwellSeconds: 5,
		}
		if err := store.Save(rec); err != nil {
			t.Fatalf("failed to save decision %s: %v", id, err)
		}
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	errCh := make(chan error, numDecisions)

	overallStart := time.Now()

	for i := 0; i < numDecisions; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("dec-parallel-%d", idx)

			windows[idx].start = time.Now()
			resp, err := sm.SubmitAction(ctx, id, &ApprovalActionRequest{
				ApproverID:   fmt.Sprintf("approver-%d", idx),
				Action:       ActionApprove,
				DwellSeconds: 10,
				SignerType:   "instrumented",
			})
			windows[idx].end = time.Now()

			if err != nil {
				errCh <- fmt.Errorf("decision %s failed: %w", id, err)
				return
			}
			if resp.Status != StatusApproved {
				errCh <- fmt.Errorf("decision %s unexpected status: %s", id, resp.Status)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	overallElapsed := time.Since(overallStart)

	for err := range errCh {
		t.Fatal(err)
	}

	// Empirical Proof 1: Total time must be far below serial execution (800ms)
	// Typically finishes in ~90-180ms on multi-core CPU.
	if overallElapsed > 500*time.Millisecond {
		t.Errorf("FAIL: Cross-decision concurrency failed! Total elapsed time %v exceeds 500ms threshold (serial would be 800ms+)", overallElapsed)
	} else {
		t.Logf("PASS: 10 distinct decisions completed in %v (< 500ms threshold; sequential would take >= 800ms)", overallElapsed)
	}

	// Empirical Proof 2: Overlap check - verify that concurrent decision time windows overlap
	overlapCount := 0
	for i := 0; i < numDecisions; i++ {
		for j := i + 1; j < numDecisions; j++ {
			// Window overlap: max(start_i, start_j) < min(end_i, end_j)
			maxStart := windows[i].start
			if windows[j].start.After(maxStart) {
				maxStart = windows[j].start
			}
			minEnd := windows[i].end
			if windows[j].end.Before(minEnd) {
				minEnd = windows[j].end
			}
			if maxStart.Before(minEnd) {
				overlapCount++
			}
		}
	}

	if overlapCount == 0 {
		t.Errorf("FAIL: No overlapping execution windows detected between distinct decision IDs! Decisions were serialized.")
	} else {
		t.Logf("PASS: Detected %d overlapping execution window pairs among %d concurrent decisions.", overlapCount, numDecisions*(numDecisions-1)/2)
	}
}

// TestAdversarial_KeyMutex_RapidDoubleClicksStrictlySerialized
// Proves that rapid double-clicks on the same decision ID are strictly serialized.
// Never allow multiple concurrent executions in critical section for the same decision ID.
func TestAdversarial_KeyMutex_RapidDoubleClicksStrictlySerialized(t *testing.T) {
	store := NewMemoryApprovalStore()
	fourEyes := fourofeyes.NewEngine()
	dwellEngine := dwell.NewEngine()
	registry := signer.NewRegistry()

	// Instrumented signer with artificial delay
	mockSigner := &mockInstrumentedSigner{signDelay: 15 * time.Millisecond}
	registry.Register(mockSigner)

	sm := NewApprovalStateMachine(store, fourEyes, dwellEngine, registry)

	const decisionID = "dec-rapid-double-click"
	rec := &ApprovalDecisionRecord{
		DecisionID:      decisionID,
		CreatorID:       "originator-user",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	if err := store.Save(rec); err != nil {
		t.Fatalf("failed to save initial record: %v", err)
	}

	const numClicks = 40
	var wg sync.WaitGroup
	var successCount int32
	var terminalErrorCount int32
	var otherErrorCount int32

	ctx := context.Background()

	// Trigger 40 simultaneous clicks on the exact same decision ID
	for i := 0; i < numClicks; i++ {
		wg.Add(1)
		go func(clickIndex int) {
			defer wg.Done()

			resp, err := sm.SubmitAction(ctx, decisionID, &ApprovalActionRequest{
				ApproverID:   "approver-same-user",
				Action:       ActionApprove,
				DwellSeconds: 15,
				SignerType:   "instrumented",
			})

			if err == nil && resp != nil && resp.Status == StatusApproved {
				atomic.AddInt32(&successCount, 1)
			} else if err != nil {
				var appErr *ApprovalError
				if errors.As(err, &appErr) && appErr.Code == "TERMINAL_STATE" {
					atomic.AddInt32(&terminalErrorCount, 1)
				} else {
					atomic.AddInt32(&otherErrorCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	// Empirical Proof 1: Max in-flight signing operations for this key must be strictly 1!
	maxInFlight := atomic.LoadInt32(&mockSigner.maxActiveSigns)
	if maxInFlight > 1 {
		t.Fatalf("FAIL: Concurrency violation! Detected %d concurrent active operations in critical section for key %s (must be strictly 1)", maxInFlight, decisionID)
	} else {
		t.Logf("PASS: Max in-flight critical section count is %d (strictly serialized)", maxInFlight)
	}

	// Empirical Proof 2: Exactly 1 approval must succeed; all others rejected
	if successCount != 1 {
		t.Fatalf("FAIL: Expected exactly 1 successful approval, got %d", successCount)
	}
	if terminalErrorCount != numClicks-1 {
		t.Errorf("Expected %d TERMINAL_STATE rejections, got %d (other errors: %d)", numClicks-1, terminalErrorCount, otherErrorCount)
	}

	// Empirical Proof 3: Stored record consistency
	finalRecord, err := store.Get(decisionID)
	if err != nil {
		t.Fatalf("failed to get final record: %v", err)
	}
	if finalRecord.Status != StatusApproved {
		t.Errorf("expected final status APPROVED, got %s", finalRecord.Status)
	}
	if len(finalRecord.Approvals) != 1 {
		t.Errorf("expected exactly 1 approval record, got %d", len(finalRecord.Approvals))
	}
	if finalRecord.Version != 1 {
		t.Errorf("expected version 1, got %d", finalRecord.Version)
	}
}

// TestAdversarial_KeyMutex_LockPruningNoMemoryLeak
// Proves that KeyMutex prunes keys from its internal map when references reach zero,
// preventing long-term memory leaks.
func TestAdversarial_KeyMutex_LockPruningNoMemoryLeak(t *testing.T) {
	km := NewKeyMutex()

	const numKeys = 200
	var wg sync.WaitGroup

	for i := 0; i < numKeys; i++ {
		wg.Add(1)
		key := fmt.Sprintf("key-%d", i)
		go func(k string) {
			defer wg.Done()
			unlock := km.Lock(k)
			time.Sleep(1 * time.Millisecond)
			unlock()
		}(key)
	}

	wg.Wait()

	km.mu.Lock()
	remainingLocks := len(km.locks)
	km.mu.Unlock()

	if remainingLocks != 0 {
		t.Fatalf("FAIL: Memory leak detected in KeyMutex! Expected 0 remaining locks, found %d", remainingLocks)
	}
	t.Logf("PASS: KeyMutex successfully pruned all %d transient locks to 0", numKeys)
}

// ---------------------------------------------------------------------------
// 2. Dwell Time Verification With Zero Heartbeats Tests
// ---------------------------------------------------------------------------

// TestAdversarial_Dwell_ZeroHeartbeatSessionRejected
// Proves that passing a session_token with 0 accumulated seconds must be rejected
// with HTTP 422 DWELL_TIME_NOT_MET, while sufficient viewing time succeeds.
func TestAdversarial_Dwell_ZeroHeartbeatSessionRejected(t *testing.T) {
	sm, _ := setupTestStateMachine()

	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-dwell-zero-hb-test",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 12,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()

	// Scenario A: session_token never received any heartbeats at all
	respA, errA := sm.SubmitAction(ctx, "dec-dwell-zero-hb-test", &ApprovalActionRequest{
		ApproverID:   "approver-test",
		Action:       ActionApprove,
		DwellSeconds: 15, // Claimed dwell >= 12
		SessionToken: "unrecorded-session-xyz",
	})
	if errA == nil {
		t.Fatalf("Scenario A: Expected DwellTimeNotMet error for unrecorded session, got success: %+v", respA)
	}
	var appErrA *ApprovalError
	if !errors.As(errA, &appErrA) {
		t.Fatalf("Scenario A: Expected ApprovalError, got: %T", errA)
	}
	if appErrA.HTTPStatus != 422 || appErrA.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("Scenario A: Expected HTTP 422 DWELL_TIME_NOT_MET, got %d %s", appErrA.HTTPStatus, appErrA.Code)
	}
	if actual, ok := appErrA.Details["elapsed_seconds"].(int); !ok || actual != 0 {
		t.Errorf("Scenario A: Expected elapsed_seconds: 0, got %v", appErrA.Details["elapsed_seconds"])
	}

	// Scenario B: session_token received 0ms heartbeat (incrementalMS = 0)
	const sessZeroMS = "sess-zero-ms"
	_, _, _, _ = sm.dwellEngine.RecordHeartbeat(sessZeroMS, "dec-dwell-zero-hb-test", "approver-test", 0, true)
	respB, errB := sm.SubmitAction(ctx, "dec-dwell-zero-hb-test", &ApprovalActionRequest{
		ApproverID:   "approver-test",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SessionToken: sessZeroMS,
	})
	if errB == nil {
		t.Fatalf("Scenario B: Expected DwellTimeNotMet error for 0ms heartbeat session, got success: %+v", respB)
	}
	var appErrB *ApprovalError
	if !errors.As(errB, &appErrB) || appErrB.HTTPStatus != 422 || appErrB.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("Scenario B: Expected HTTP 422 DWELL_TIME_NOT_MET, got %v", errB)
	}

	// Scenario C: session_token received heartbeats with tabFocused = false (unfocused window)
	const sessUnfocused = "sess-unfocused"
	for i := 0; i < 5; i++ {
		_, _, _, _ = sm.dwellEngine.RecordHeartbeat(sessUnfocused, "dec-dwell-zero-hb-test", "approver-test", 3000, false)
	}
	respC, errC := sm.SubmitAction(ctx, "dec-dwell-zero-hb-test", &ApprovalActionRequest{
		ApproverID:   "approver-test",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SessionToken: sessUnfocused,
	})
	if errC == nil {
		t.Fatalf("Scenario C: Expected DwellTimeNotMet error for unfocused session, got success: %+v", respC)
	}
	var appErrC *ApprovalError
	if !errors.As(errC, &appErrC) || appErrC.HTTPStatus != 422 || appErrC.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("Scenario C: Expected HTTP 422 DWELL_TIME_NOT_MET, got %v", errC)
	}

	// Scenario D: session_token with insufficient viewing time (e.g. 6s accumulated < 12s required)
	const sessPartial = "sess-partial"
	for i := 0; i < 2; i++ {
		_, _, _, _ = sm.dwellEngine.RecordHeartbeat(sessPartial, "dec-dwell-zero-hb-test", "approver-test", 3000, true)
	}
	respD, errD := sm.SubmitAction(ctx, "dec-dwell-zero-hb-test", &ApprovalActionRequest{
		ApproverID:   "approver-test",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SessionToken: sessPartial,
	})
	if errD == nil {
		t.Fatalf("Scenario D: Expected DwellTimeNotMet error for 6s < 12s session, got success: %+v", respD)
	}
	var appErrD *ApprovalError
	if !errors.As(errD, &appErrD) || appErrD.HTTPStatus != 422 || appErrD.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("Scenario D: Expected HTTP 422 DWELL_TIME_NOT_MET, got %v", errD)
	}
	if actual, ok := appErrD.Details["elapsed_seconds"].(int); !ok || actual != 6 {
		t.Errorf("Scenario D: Expected elapsed_seconds: 6, got %v", appErrD.Details["elapsed_seconds"])
	}

	// Scenario E: session_token with sufficient viewing time (13s >= 12s) MUST SUCCEED
	const sessValid = "sess-valid-13s"
	// 5 ticks of 2600ms = 13,000ms = 13s
	for i := 0; i < 5; i++ {
		_, _, _, _ = sm.dwellEngine.RecordHeartbeat(sessValid, "dec-dwell-zero-hb-test", "approver-test", 2600, true)
	}
	respE, errE := sm.SubmitAction(ctx, "dec-dwell-zero-hb-test", &ApprovalActionRequest{
		ApproverID:   "approver-test",
		Action:       ActionApprove,
		DwellSeconds: 13,
		SessionToken: sessValid,
		SignerType:   "internal",
	})
	if errE != nil {
		t.Fatalf("Scenario E: Expected success with sufficient dwell heartbeats, got error: %v", errE)
	}
	if respE.Status != StatusApproved {
		t.Errorf("Scenario E: Expected status APPROVED, got %s", respE.Status)
	}
	t.Logf("PASS: Dwell zero-heartbeat rejection and sufficient viewing time acceptance verified.")
}

// ---------------------------------------------------------------------------
// 3. Memory Isolation in store.go Tests
// ---------------------------------------------------------------------------

// TestAdversarial_Store_MemoryIsolation_ScoreAndNestedStructures
// Proves that mutating *record.Score (and slices/maps) on a fetched decision record
// does NOT alter the record in MemoryApprovalStore.
func TestAdversarial_Store_MemoryIsolation_ScoreAndNestedStructures(t *testing.T) {
	store := NewMemoryApprovalStore()

	initialScore := 750.25
	origRecord := &ApprovalDecisionRecord{
		DecisionID:      "dec-store-isolation-test",
		CorrelationID:   "corr-orig",
		AISystemID:      "model-credit",
		SystemType:      "ml",
		Score:           &initialScore,
		RequiredRoles:   []string{"risk_officer", "compliance_lead"},
		PIIDetected:     []string{"CCCD", "PHONE"},
		Payload: map[string]interface{}{
			"amount_vnd":  500000000.0,
			"customer_id": "cust-001",
		},
		Approvals: []ApproverAuditRecord{
			{
				ApproverID:   "approver-1",
				Action:       ActionApprove,
				DwellSeconds: 15,
			},
		},
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Save(origRecord); err != nil {
		t.Fatalf("failed to save initial record: %v", err)
	}

	// 1. Mutate the original struct that was passed to Save
	// (Proves store saved a deep clone rather than retaining the caller's struct)
	*origRecord.Score = 111.11
	origRecord.RequiredRoles[0] = "MUTATED_ORIG_ROLE"
	origRecord.Payload["amount_vnd"] = 0.0

	// 2. Fetch record copy from store
	r1, err := store.Get("dec-store-isolation-test")
	if err != nil {
		t.Fatalf("failed to get r1: %v", err)
	}
	if r1.Score == nil || *r1.Score != 750.25 {
		t.Fatalf("FAIL: Mutating origRecord corrupted store! Expected 750.25, got %v", r1.Score)
	}
	if r1.RequiredRoles[0] != "risk_officer" {
		t.Fatalf("FAIL: Mutating origRecord.RequiredRoles corrupted store!")
	}
	if r1.Payload["amount_vnd"] != 500000000.0 {
		t.Fatalf("FAIL: Mutating origRecord.Payload corrupted store!")
	}

	// 3. Mutate r1 in place
	*r1.Score = 999.99
	r1.RequiredRoles = append(r1.RequiredRoles, "INJECTED_ROLE")
	r1.RequiredRoles[0] = "MUTATED_R1_ROLE"
	r1.PIIDetected = append(r1.PIIDetected, "INJECTED_PII")
	r1.Payload["amount_vnd"] = -999999.0
	r1.Payload["malicious_key"] = true
	r1.Approvals[0].ApproverID = "hacked-approver"
	r1.Approvals = append(r1.Approvals, ApproverAuditRecord{ApproverID: "ghost"})

	// 4. Fetch second record copy from store (r2)
	r2, err := store.Get("dec-store-isolation-test")
	if err != nil {
		t.Fatalf("failed to get r2: %v", err)
	}

	// Assert complete pointer address independence
	if r1.Score == r2.Score {
		t.Fatalf("FAIL: r1.Score and r2.Score point to the exact same address %p!", r1.Score)
	}
	if *r2.Score != 750.25 {
		t.Fatalf("FAIL: Mutating *r1.Score altered store record! Expected 750.25, got %f", *r2.Score)
	}
	if len(r2.RequiredRoles) != 2 || r2.RequiredRoles[0] != "risk_officer" {
		t.Fatalf("FAIL: RequiredRoles was mutated in store! Got %v", r2.RequiredRoles)
	}
	if len(r2.PIIDetected) != 2 || r2.PIIDetected[0] != "CCCD" {
		t.Fatalf("FAIL: PIIDetected was mutated in store! Got %v", r2.PIIDetected)
	}
	if r2.Payload["amount_vnd"] != 500000000.0 || r2.Payload["malicious_key"] != nil {
		t.Fatalf("FAIL: Payload map was mutated in store! Got %v", r2.Payload)
	}
	if len(r2.Approvals) != 1 || r2.Approvals[0].ApproverID != "approver-1" {
		t.Fatalf("FAIL: Approvals slice was mutated in store! Got %v", r2.Approvals)
	}

	// 5. Test store.List() isolation
	recordsList := store.List()
	if len(recordsList) != 1 {
		t.Fatalf("expected 1 record in list, got %d", len(recordsList))
	}
	*recordsList[0].Score = 333.33
	recordsList[0].Payload["list_mutation"] = true

	r3, _ := store.Get("dec-store-isolation-test")
	if *r3.Score != 750.25 || r3.Payload["list_mutation"] != nil {
		t.Fatalf("FAIL: Mutating store.List() element corrupted store! Got score %f", *r3.Score)
	}

	t.Logf("PASS: Memory isolation in store.go completely verified. Score pointer and all collections are deep-copied.")
}
