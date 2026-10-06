package dwell

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrDwellTimeNotMet = errors.New("DWELL_TIME_NOT_MET")
)

// DwellError represents a structured dwell time violation.
type DwellError struct {
	Actual   int
	Required int
}

func (e *DwellError) Error() string {
	return fmt.Sprintf("DWELL_TIME_NOT_MET: Viewing duration %ds < required %ds", e.Actual, e.Required)
}

// ComplexityInput encapsulates decision payload metrics for reading time estimation.
type ComplexityInput struct {
	TokenCount   int
	CharCount    int
	FeatureCount int
	HasSHAP      bool
	HasPII       bool
	IsHighRisk   bool
}

// Session represents an active viewing session from an interactive client.
type Session struct {
	SessionID           string
	DecisionID          string
	ViewerID            string
	StartTime           time.Time
	LastHeartbeatTime   time.Time
	AccumulatedActiveMS int64
}

// Engine manages dwell time calculation and session telemetry.
type Engine struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewEngine constructs a new dwell time Engine.
func NewEngine() *Engine {
	return &Engine{
		sessions: make(map[string]*Session),
	}
}

// CalculateMinimumDwell calculates payload-adjusted reading duration.
// Formula: clamp(T_base + Tokens/100 + Features/5 + SHAP(2s) + PII(2s), floor, ceiling)
func (e *Engine) CalculateMinimumDwell(input ComplexityInput, configFloor int) int {
	baseSec := 5
	if input.IsHighRisk {
		baseSec = 10
	}
	if configFloor > 0 {
		baseSec = configFloor
	}

	tokenSec := input.TokenCount / 100
	if tokenSec == 0 && input.CharCount > 0 {
		tokenSec = input.CharCount / 500
	}

	featureSec := input.FeatureCount / 5
	shapSec := 0
	if input.HasSHAP {
		shapSec = 2
	}
	piiSec := 0
	if input.HasPII {
		piiSec = 2
	}

	total := baseSec + tokenSec + featureSec + shapSec + piiSec
	floor := 5
	if configFloor > 0 {
		floor = configFloor
	} else if input.IsHighRisk {
		floor = 10
	}

	if total < floor {
		total = floor
	}
	if total > 120 {
		total = 120
	}
	return total
}

// RecordHeartbeat records active viewing telemetry, clamping tick increments to max 3000ms.
func (e *Engine) RecordHeartbeat(sessionID, decisionID, viewerID string, incrementalMS int, tabFocused bool) (accumulatedMS int64, remainingSec int, dwellMet bool, err error) {
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-%s", decisionID, viewerID)
	}

	e.mu.Lock()
	sess, exists := e.sessions[sessionID]
	if !exists {
		sess = &Session{
			SessionID:         sessionID,
			DecisionID:        decisionID,
			ViewerID:          viewerID,
			StartTime:         time.Now().UTC(),
			LastHeartbeatTime: time.Now().UTC(),
		}
		e.sessions[sessionID] = sess
	}

	now := time.Now().UTC()
	sess.LastHeartbeatTime = now

	if tabFocused && incrementalMS > 0 {
		// Clamp tick to max 3,000ms to prevent client spoofing
		if incrementalMS > 3000 {
			incrementalMS = 3000
		}
		sess.AccumulatedActiveMS += int64(incrementalMS)
	}
	accumulated := sess.AccumulatedActiveMS
	e.mu.Unlock()

	return accumulated, 0, false, nil
}

// GetAccumulatedSeconds returns active accumulated dwell time in seconds for a session.
func (e *Engine) GetAccumulatedSeconds(sessionID string) int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	sess, exists := e.sessions[sessionID]
	if !exists {
		return 0
	}
	return int(sess.AccumulatedActiveMS / 1000)
}

// ValidateDwell verifies that dwell requirements are satisfied.
func (e *Engine) ValidateDwell(requiredSeconds, submittedSeconds int, sessionID string) error {
	if requiredSeconds <= 0 {
		requiredSeconds = 10
	}

	// 1. Direct submitted dwell check
	if submittedSeconds < requiredSeconds {
		return &DwellError{Actual: submittedSeconds, Required: requiredSeconds}
	}

	// 2. If session token was provided, cross-verify active accumulated seconds
	if sessionID != "" {
		accumSec := e.GetAccumulatedSeconds(sessionID)
		if accumSec < requiredSeconds {
			return &DwellError{Actual: accumSec, Required: requiredSeconds}
		}
	}

	return nil
}
