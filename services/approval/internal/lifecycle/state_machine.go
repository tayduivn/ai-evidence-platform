package lifecycle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"ei-evidence-platform/services/approval/internal/canonical"
	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/fourofeyes"
	"ei-evidence-platform/services/approval/internal/signer"
)

// KeyMutex provides per-key mutual exclusion to prevent global lock contention across decisions.
type KeyMutex struct {
	mu    sync.Mutex
	locks map[string]*keyLock
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

func NewKeyMutex() *KeyMutex {
	return &KeyMutex{
		locks: make(map[string]*keyLock),
	}
}

// Lock acquires a mutex for the specified key and returns an unlock closure.
func (km *KeyMutex) Lock(key string) func() {
	km.mu.Lock()
	kl, exists := km.locks[key]
	if !exists {
		kl = &keyLock{}
		km.locks[key] = kl
	}
	kl.refs++
	km.mu.Unlock()

	kl.mu.Lock()
	return func() {
		kl.mu.Unlock()
		km.mu.Lock()
		kl.refs--
		if kl.refs == 0 {
			delete(km.locks, key)
		}
		km.mu.Unlock()
	}
}

// ApprovalStateMachine coordinates the approval lifecycle, 4-Eyes rules, dwell time, and digital signing.
type ApprovalStateMachine struct {
	keyMu          *KeyMutex
	store          ApprovalStore
	fourEyesEngine *fourofeyes.Engine
	dwellEngine    *dwell.Engine
	signerRegistry *signer.Registry
}

// NewApprovalStateMachine creates a fully wired state machine.
func NewApprovalStateMachine(
	store ApprovalStore,
	fourEyesEngine *fourofeyes.Engine,
	dwellEngine *dwell.Engine,
	signerRegistry *signer.Registry,
) *ApprovalStateMachine {
	if fourEyesEngine == nil {
		fourEyesEngine = fourofeyes.NewEngine()
	}
	if dwellEngine == nil {
		dwellEngine = dwell.NewEngine()
	}
	if signerRegistry == nil {
		signerRegistry = signer.NewRegistry()
	}

	return &ApprovalStateMachine{
		keyMu:          NewKeyMutex(),
		store:          store,
		fourEyesEngine: fourEyesEngine,
		dwellEngine:    dwellEngine,
		signerRegistry: signerRegistry,
	}
}

// GetStore returns the underlying ApprovalStore.
func (sm *ApprovalStateMachine) GetStore() ApprovalStore {
	return sm.store
}

// GetDwellEngine returns the DwellEngine.
func (sm *ApprovalStateMachine) GetDwellEngine() *dwell.Engine {
	return sm.dwellEngine
}

// SubmitAction executes a transition attempt on a decision record.
func (sm *ApprovalStateMachine) SubmitAction(
	ctx context.Context,
	decisionID string,
	req *ApprovalActionRequest,
) (*ApprovalActionResponse, error) {
	if decisionID == "" {
		return nil, ErrDecisionNotFound("")
	}

	unlock := sm.keyMu.Lock(decisionID)
	defer unlock()

	record, err := sm.store.Get(decisionID)
	if err != nil {
		return nil, err
	}

	// 1. TTL Expiration Check
	if record.Status == StatusExpired || (!record.ExpiresAt.IsZero() && time.Now().UTC().After(record.ExpiresAt)) {
		record.Status = StatusExpired
		record.UpdatedAt = time.Now().UTC()
		_ = sm.store.Save(record)
		return nil, ErrDecisionExpired()
	}

	// 2. Terminal State Guard (APPROVED, REJECTED)
	if record.Status == StatusApproved || record.Status == StatusRejected {
		return nil, ErrTerminalState(record.Status)
	}

	// 3. Optimistic Versioning Guard (if specified by caller)
	if req.ExpectedVersion > 0 && record.Version != req.ExpectedVersion {
		return nil, ErrOptimisticLock(req.ExpectedVersion, record.Version)
	}

	// 4. Creator Separation Guard
	if req.ApproverID != "" && record.CreatorID != "" && req.ApproverID == record.CreatorID {
		return nil, ErrCreatorCannotApprove()
	}

	// 5. Anti-Rubberstamping Dwell Time Guard
	minDwell := record.MinDwellSeconds
	if minDwell <= 0 {
		minDwell = 10
	}
	if err := sm.dwellEngine.ValidateDwell(minDwell, req.DwellSeconds, req.SessionToken); err != nil {
		var dwellErr *dwell.DwellError
		if errors.As(err, &dwellErr) {
			return nil, ErrDwellTimeNotMet(dwellErr.Actual, dwellErr.Required)
		}
		return nil, ErrDwellTimeNotMet(req.DwellSeconds, minDwell)
	}

	// 6. Handle REJECT Action (Immediate Terminal Rejection)
	if req.Action == ActionReject {
		record.Status = StatusRejected
		record.UpdatedAt = time.Now().UTC()
		record.Version++
		auditRecord := ApproverAuditRecord{
			ApproverID:   req.ApproverID,
			Role:         req.Role,
			Action:       ActionReject,
			DwellSeconds: req.DwellSeconds,
			SignerType:   req.SignerType,
			Comment:      req.Comment,
			Timestamp:    time.Now().UTC(),
		}
		record.Approvals = append(record.Approvals, auditRecord)
		if err := sm.store.Save(record); err != nil {
			return nil, err
		}
		return &ApprovalActionResponse{
			Status:     StatusRejected,
			StatusCode: 200,
			Message:    "Decision REJECTED",
			DecisionID: record.DecisionID,
			Version:    record.Version,
			StepIndex:  len(record.Approvals),
		}, nil
	}

	// 7. Validate Valid Action
	if req.Action != ActionApprove {
		return nil, ErrInvalidAction(req.Action)
	}

	// 8. 4-Eyes & Duplicate Approver Checks
	existingApprovers := make([]string, 0, len(record.Approvals))
	for _, a := range record.Approvals {
		existingApprovers = append(existingApprovers, a.ApproverID)
	}
	if err := sm.fourEyesEngine.ValidateApprovalAction(
		record.CreatorID,
		req.ApproverID,
		string(req.Action),
		existingApprovers,
		req.Role,
		record.RequiredRoles,
	); err != nil {
		if errors.Is(err, fourofeyes.ErrCreatorCannotApprove) {
			return nil, ErrCreatorCannotApprove()
		}
		if errors.Is(err, fourofeyes.ErrDuplicateApprover) {
			return nil, ErrDuplicateApprover()
		}
		return nil, &ApprovalError{
			Code:       "VALIDATION_FAILED",
			Message:    err.Error(),
			HTTPStatus: 400,
		}
	}

	// 9. Digital Signing
	signerType := req.SignerType
	if signerType == "" {
		signerType = "internal"
	}

	s, err := sm.signerRegistry.Get(signerType)
	if err != nil || s == nil {
		return nil, ErrSignerNotFound(signerType, err)
	}

	var sigBytes []byte
	var certPEM []byte

	signPayload := canonical.DecisionSignPayload{
		DecisionID:       record.DecisionID,
		ApproverID:       req.ApproverID,
		Action:           string(req.Action),
		DwellTimeSeconds: req.DwellSeconds,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}

	sigHex := req.SignatureHex
	certStr := req.CertificatePEM

	// If no client-provided signature was supplied, perform server-side signing via registered signer
	if sigHex == "" {
		canonBytes, cErr := canonical.Marshal(signPayload)
		if cErr != nil {
			return nil, &ApprovalError{
				Code:       "CANONICAL_ERROR",
				Message:    fmt.Sprintf("canonical error: %v", cErr),
				HTTPStatus: http.StatusInternalServerError,
			}
		}

		var signErr error
		sigBytes, certPEM, signErr = s.Sign(ctx, canonBytes)
		if signErr != nil {
			return nil, ErrSigningFailed(signErr)
		}
		if len(sigBytes) == 0 {
			return nil, ErrSigningFailed(errors.New("empty signature bytes returned by signer"))
		}

		sigHex = hex.EncodeToString(sigBytes)
		if len(certPEM) > 0 {
			certStr = string(certPEM)
		}
	}

	// 10. Append Approval Audit Record
	auditRecord := ApproverAuditRecord{
		ApproverID:     req.ApproverID,
		Role:           req.Role,
		Action:         ActionApprove,
		DwellSeconds:   req.DwellSeconds,
		SignerType:     signerType,
		SignatureHex:   sigHex,
		SignedPayload:  signPayload,
		CertificatePEM: certStr,
		Comment:        req.Comment,
		Timestamp:      time.Now().UTC(),
	}
	record.Approvals = append(record.Approvals, auditRecord)
	record.Version++
	record.UpdatedAt = time.Now().UTC()

	// 11. State Machine Transition Evaluation
	var respMsg string
	if record.Requires4Eyes {
		if len(record.Approvals) == 1 {
			record.Status = StatusAwaitingSecondApproval
			respMsg = "Awaiting second approval"
		} else if len(record.Approvals) >= 2 {
			record.Status = StatusApproved
			respMsg = "Decision APPROVED with 4-Eyes confirmation"
		}
	} else {
		record.Status = StatusApproved
		respMsg = "Decision APPROVED"
	}

	if err := sm.store.Save(record); err != nil {
		return nil, err
	}

	return &ApprovalActionResponse{
		Status:       record.Status,
		StatusCode:   200,
		Message:      respMsg,
		DecisionID:   record.DecisionID,
		Version:      record.Version,
		StepIndex:    len(record.Approvals),
		SignatureHex: sigHex,
	}, nil
}
