package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/fourofeyes"
	"ei-evidence-platform/services/approval/internal/signer"
)

func setupTestStateMachine() (*ApprovalStateMachine, *signer.Registry) {
	store := NewMemoryApprovalStore()
	fourEyes := fourofeyes.NewEngine()
	dwellEngine := dwell.NewEngine()
	registry := signer.NewRegistry()

	internalSigner, _ := signer.NewInternalSigner(signer.InternalSignerConfig{
		ApproverID: "test-approver",
	})
	tokenSigner, _ := signer.NewCAVNTokenSigner(signer.CAVNTokenConfig{
		ApproverName: "Nguyen Van Dac",
	})
	registry.Register(internalSigner)
	registry.Register(tokenSigner)

	sm := NewApprovalStateMachine(store, fourEyes, dwellEngine, registry)
	return sm, registry
}

func TestStateMachine_InitialPendingState(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-1",
		CreatorID:       "loan-officer-01",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	saved, err := sm.store.Get("dec-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved.Status != StatusPending {
		t.Errorf("expected PENDING, got %s", saved.Status)
	}
}

func TestStateMachine_CreatorCannotSelfApprove(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-creator",
		CreatorID:       "creator-user",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	req := &ApprovalActionRequest{
		ApproverID:   "creator-user",
		Action:       ActionApprove,
		DwellSeconds: 15,
	}

	_, err := sm.SubmitAction(ctx, "dec-creator", req)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	var appErr *ApprovalError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected ApprovalError, got: %T", err)
	}
	if appErr.HTTPStatus != 403 || appErr.Code != "CREATOR_CANNOT_APPROVE" {
		t.Errorf("expected HTTP 403 CREATOR_CANNOT_APPROVE, got: %d %s", appErr.HTTPStatus, appErr.Code)
	}
}

func TestStateMachine_DwellTimeNotMet(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-dwell",
		CreatorID:       "creator-user",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	req := &ApprovalActionRequest{
		ApproverID:   "approver-01",
		Action:       ActionApprove,
		DwellSeconds: 5, // Below 10s
	}

	_, err := sm.SubmitAction(ctx, "dec-dwell", req)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	var appErr *ApprovalError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected ApprovalError, got: %T", err)
	}
	if appErr.HTTPStatus != 422 || appErr.Code != "DWELL_TIME_NOT_MET" {
		t.Errorf("expected HTTP 422 DWELL_TIME_NOT_MET, got: %d %s", appErr.HTTPStatus, appErr.Code)
	}
}

func TestStateMachine_FourEyesFullFlow(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-4eyes",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()

	// 1. First approval by approver-01
	resp1, err := sm.SubmitAction(ctx, "dec-4eyes", &ApprovalActionRequest{
		ApproverID:   "approver-01",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SignerType:   "internal",
	})
	if err != nil {
		t.Fatalf("first approval failed: %v", err)
	}
	if resp1.Status != StatusAwaitingSecondApproval || resp1.Message != "Awaiting second approval" {
		t.Errorf("expected AWAITING_SECOND_APPROVAL, got %s: %s", resp1.Status, resp1.Message)
	}
	if resp1.SignatureHex == "" {
		t.Errorf("expected non-empty signature hex")
	}

	// 2. Duplicate approval by approver-01 must fail
	_, err = sm.SubmitAction(ctx, "dec-4eyes", &ApprovalActionRequest{
		ApproverID:   "approver-01",
		Action:       ActionApprove,
		DwellSeconds: 20,
		SignerType:   "internal",
	})
	if err == nil {
		t.Fatalf("expected duplicate approver error, got nil")
	}
	var appErr *ApprovalError
	if !errors.As(err, &appErr) || appErr.HTTPStatus != 400 || appErr.Code != "DUPLICATE_APPROVER" {
		t.Errorf("expected HTTP 400 DUPLICATE_APPROVER, got: %v", err)
	}

	// 3. Second approval by distinct approver-02
	resp2, err := sm.SubmitAction(ctx, "dec-4eyes", &ApprovalActionRequest{
		ApproverID:   "approver-02",
		Action:       ActionApprove,
		DwellSeconds: 20,
		SignerType:   "ca_vn_token",
	})
	if err != nil {
		t.Fatalf("second approval failed: %v", err)
	}
	if resp2.Status != StatusApproved || resp2.Message != "Decision APPROVED with 4-Eyes confirmation" {
		t.Errorf("expected APPROVED with 4-Eyes, got %s: %s", resp2.Status, resp2.Message)
	}

	// 4. Action on terminal APPROVED state must fail
	_, err = sm.SubmitAction(ctx, "dec-4eyes", &ApprovalActionRequest{
		ApproverID:   "approver-03",
		Action:       ActionApprove,
		DwellSeconds: 25,
	})
	if err == nil {
		t.Fatalf("expected terminal state error, got nil")
	}
	if !errors.As(err, &appErr) || appErr.HTTPStatus != 400 || appErr.Code != "TERMINAL_STATE" {
		t.Errorf("expected HTTP 400 TERMINAL_STATE, got: %v", err)
	}
}

func TestStateMachine_SingleApproverFlow(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-single",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 5,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	resp, err := sm.SubmitAction(ctx, "dec-single", &ApprovalActionRequest{
		ApproverID:   "approver-01",
		Action:       ActionApprove,
		DwellSeconds: 10,
	})
	if err != nil {
		t.Fatalf("approval failed: %v", err)
	}
	if resp.Status != StatusApproved || resp.Message != "Decision APPROVED" {
		t.Errorf("expected APPROVED, got %s: %s", resp.Status, resp.Message)
	}
}

func TestStateMachine_RejectFlow(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-reject",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	resp, err := sm.SubmitAction(ctx, "dec-reject", &ApprovalActionRequest{
		ApproverID:   "reviewer-01",
		Action:       ActionReject,
		DwellSeconds: 12,
		Comment:      "Suspicious borrower profile",
	})
	if err != nil {
		t.Fatalf("rejection failed: %v", err)
	}
	if resp.Status != StatusRejected || resp.Message != "Decision REJECTED" {
		t.Errorf("expected REJECTED, got %s: %s", resp.Status, resp.Message)
	}
}

func TestStateMachine_TTLExpiration(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-expired",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
		ExpiresAt:       time.Now().UTC().Add(-10 * time.Minute), // Already expired
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	_, err := sm.SubmitAction(ctx, "dec-expired", &ApprovalActionRequest{
		ApproverID:   "approver-01",
		Action:       ActionApprove,
		DwellSeconds: 15,
	})
	if err == nil {
		t.Fatalf("expected expiration error, got nil")
	}

	var appErr *ApprovalError
	if !errors.As(err, &appErr) || appErr.Code != "DECISION_EXPIRED" {
		t.Errorf("expected DECISION_EXPIRED, got: %v", err)
	}
}

func TestStateMachine_ConcurrentDoubleApproval(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-race",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   true,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	const numGoroutines = 20
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := sm.SubmitAction(ctx, "dec-race", &ApprovalActionRequest{
				ApproverID:   "approver-same",
				Action:       ActionApprove,
				DwellSeconds: 15,
			})
			if err == nil && resp.StatusCode == 200 {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly 1 approval by "approver-same" must succeed! The remaining 19 must fail with DUPLICATE_APPROVER or TERMINAL_STATE.
	if successCount != 1 {
		t.Fatalf("expected exactly 1 approval to succeed, got %d", successCount)
	}
}

type mockFailingSigner struct{}

func (m *mockFailingSigner) Type() string { return "failing" }
func (m *mockFailingSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("HSM connection timeout")
}
func (m *mockFailingSigner) Verify(ctx context.Context, payload, signature, certPEM []byte) (bool, error) {
	return false, nil
}
func (m *mockFailingSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	return nil, nil
}

func TestStateMachine_UnregisteredSigner_Returns400(t *testing.T) {
	sm, _ := setupTestStateMachine()
	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-unreg",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	req := &ApprovalActionRequest{
		ApproverID:   "approver-1",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SignerType:   "unregistered-signer-xyz",
	}

	resp, err := sm.SubmitAction(ctx, "dec-unreg", req)
	if err == nil {
		t.Fatalf("expected error for unregistered signer, got resp: %+v", resp)
	}

	var appErr *ApprovalError
	if !errors.As(err, &appErr) || appErr.Code != "SIGNER_NOT_FOUND" {
		t.Fatalf("expected SIGNER_NOT_FOUND error, got: %v", err)
	}
	if appErr.HTTPStatus != 400 {
		t.Errorf("expected HTTP 400, got %d", appErr.HTTPStatus)
	}

	// Verify state machine did NOT advance
	saved, _ := sm.store.Get("dec-unreg")
	if saved.Status != StatusPending {
		t.Errorf("expected StatusPending, got %s", saved.Status)
	}
	if len(saved.Approvals) != 0 {
		t.Errorf("expected 0 approvals, got %d", len(saved.Approvals))
	}
	if saved.Version != 0 {
		t.Errorf("expected version 0, got %d", saved.Version)
	}
}

func TestStateMachine_SigningFailure_RejectsWithoutAdvancing(t *testing.T) {
	sm, registry := setupTestStateMachine()
	registry.Register(&mockFailingSigner{})

	rec := &ApprovalDecisionRecord{
		DecisionID:      "dec-fail-sign",
		CreatorID:       "originator",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec)

	ctx := context.Background()
	req := &ApprovalActionRequest{
		ApproverID:   "approver-1",
		Action:       ActionApprove,
		DwellSeconds: 15,
		SignerType:   "failing",
	}

	resp, err := sm.SubmitAction(ctx, "dec-fail-sign", req)
	if err == nil {
		t.Fatalf("expected error for failing signer, got resp: %+v", resp)
	}

	var appErr *ApprovalError
	if !errors.As(err, &appErr) || appErr.Code != "SIGNING_FAILED" {
		t.Fatalf("expected SIGNING_FAILED error, got: %v", err)
	}
	if appErr.HTTPStatus != 500 {
		t.Errorf("expected HTTP 500, got %d", appErr.HTTPStatus)
	}

	// Verify state machine did NOT advance
	saved, _ := sm.store.Get("dec-fail-sign")
	if saved.Status != StatusPending {
		t.Errorf("expected StatusPending, got %s", saved.Status)
	}
	if len(saved.Approvals) != 0 {
		t.Errorf("expected 0 approvals, got %d", len(saved.Approvals))
	}
	if saved.Version != 0 {
		t.Errorf("expected version 0, got %d", saved.Version)
	}
}

type mockSlowSigner struct{}

func (m *mockSlowSigner) Type() string { return "slow" }
func (m *mockSlowSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	time.Sleep(150 * time.Millisecond)
	return []byte("slow-sig-bytes"), []byte("slow-cert"), nil
}
func (m *mockSlowSigner) Verify(ctx context.Context, payload, signature, certPEM []byte) (bool, error) {
	return true, nil
}
func (m *mockSlowSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	return [][]byte{[]byte("slow-cert")}, nil
}

func TestStateMachine_CrossDecisionConcurrency_NoGlobalBlock(t *testing.T) {
	sm, registry := setupTestStateMachine()
	registry.Register(&mockSlowSigner{})

	rec1 := &ApprovalDecisionRecord{
		DecisionID:      "dec-slow",
		CreatorID:       "originator-1",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	rec2 := &ApprovalDecisionRecord{
		DecisionID:      "dec-fast",
		CreatorID:       "originator-2",
		Status:          StatusPending,
		Requires4Eyes:   false,
		MinDwellSeconds: 10,
	}
	_ = sm.store.Save(rec1)
	_ = sm.store.Save(rec2)

	ctx := context.Background()
	var wg sync.WaitGroup
	var slowFinished, fastFinished time.Time

	wg.Add(2)

	// Goroutine 1: Submits dec-slow with slow signer (takes >= 150ms)
	go func() {
		defer wg.Done()
		_, err := sm.SubmitAction(ctx, "dec-slow", &ApprovalActionRequest{
			ApproverID:   "approver-slow",
			Action:       ActionApprove,
			DwellSeconds: 15,
			SignerType:   "slow",
		})
		if err != nil {
			t.Errorf("dec-slow failed: %v", err)
		}
		slowFinished = time.Now()
	}()

	// Wait 20ms to ensure Goroutine 1 has acquired the lock on dec-slow and entered Sign()
	time.Sleep(20 * time.Millisecond)

	// Goroutine 2: Submits dec-fast with internal signer
	go func() {
		defer wg.Done()
		start := time.Now()
		_, err := sm.SubmitAction(ctx, "dec-fast", &ApprovalActionRequest{
			ApproverID:   "approver-fast",
			Action:       ActionApprove,
			DwellSeconds: 15,
			SignerType:   "internal",
		})
		if err != nil {
			t.Errorf("dec-fast failed: %v", err)
		}
		fastFinished = time.Now()
		elapsed := fastFinished.Sub(start)
		if elapsed > 100*time.Millisecond {
			t.Errorf("dec-fast took too long (%v), was likely blocked by dec-slow!", elapsed)
		}
	}()

	wg.Wait()

	if !fastFinished.Before(slowFinished) {
		t.Errorf("dec-fast should finish before dec-slow; fast: %v, slow: %v", fastFinished, slowFinished)
	}
}

