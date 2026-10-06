package dwell

import (
	"strings"
	"testing"
)

func TestDwell_CalculateMinimumDwell(t *testing.T) {
	engine := NewEngine()

	// Low risk base: 5s
	d1 := engine.CalculateMinimumDwell(ComplexityInput{}, 0)
	if d1 != 5 {
		t.Errorf("expected 5, got %d", d1)
	}

	// High risk base: 10s
	d2 := engine.CalculateMinimumDwell(ComplexityInput{IsHighRisk: true}, 0)
	if d2 != 10 {
		t.Errorf("expected 10, got %d", d2)
	}

	// Full complexity: 500 tokens (5s) + 10 features (2s) + SHAP (2s) + PII (2s) + Base 10s = 21s
	d3 := engine.CalculateMinimumDwell(ComplexityInput{
		IsHighRisk:   true,
		TokenCount:   500,
		FeatureCount: 10,
		HasSHAP:      true,
		HasPII:       true,
	}, 0)
	if d3 != 21 {
		t.Errorf("expected 21, got %d", d3)
	}
}

func TestDwell_Validation(t *testing.T) {
	engine := NewEngine()

	// Met: 12s >= 10s
	err := engine.ValidateDwell(10, 12, "")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Exact threshold: 10s == 10s
	err = engine.ValidateDwell(10, 10, "")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Sub-threshold: 9s < 10s
	err = engine.ValidateDwell(10, 9, "")
	if err == nil {
		t.Fatalf("expected DwellError, got nil")
	}
	if !strings.Contains(err.Error(), "DWELL_TIME_NOT_MET") {
		t.Errorf("expected DWELL_TIME_NOT_MET in error message, got: %v", err)
	}

	// Zero second rubberstamp: 0s < 10s
	err = engine.ValidateDwell(10, 0, "")
	if err == nil {
		t.Fatalf("expected DwellError, got nil")
	}
}

func TestDwell_HeartbeatAndClamping(t *testing.T) {
	engine := NewEngine()
	sessID := "sess-01"

	// Focus heartbeat: 2000ms
	accum, _, _, err := engine.RecordHeartbeat(sessID, "dec-1", "user-1", 2000, true)
	if err != nil || accum != 2000 {
		t.Fatalf("unexpected heartbeat result: %d, %v", accum, err)
	}

	// Unfocused heartbeat: tabFocused=false (should not increment)
	accum, _, _, _ = engine.RecordHeartbeat(sessID, "dec-1", "user-1", 2000, false)
	if accum != 2000 {
		t.Errorf("expected 2000ms without increment, got %d", accum)
	}

	// Spoofed tick: 10,000ms (clamped to 3,000ms)
	accum, _, _, _ = engine.RecordHeartbeat(sessID, "dec-1", "user-1", 10000, true)
	if accum != 5000 {
		t.Errorf("expected clamped accumulation to 5000ms, got %d", accum)
	}
}

func TestDwell_UnregisteredSession_RejectedWhenSessionIDProvided(t *testing.T) {
	engine := NewEngine()

	// Calling ValidateDwell with an unregistered sessionID must be rejected even if submittedSeconds >= requiredSeconds
	err := engine.ValidateDwell(10, 15, "unregistered-session-id")
	if err == nil {
		t.Fatalf("expected DwellError for unregistered session, got nil")
	}
	dwellErr, ok := err.(*DwellError)
	if !ok {
		t.Fatalf("expected *DwellError, got %T: %v", err, err)
	}
	if dwellErr.Actual != 0 || dwellErr.Required != 10 {
		t.Errorf("expected Actual: 0, Required: 10, got Actual: %d, Required: %d", dwellErr.Actual, dwellErr.Required)
	}
}

func TestDwell_ZeroHeartbeatSessionRejected(t *testing.T) {
	engine := NewEngine()
	sessID := "sess-zero"

	// Register session with 0 duration
	accum := engine.GetAccumulatedSeconds(sessID)
	if accum != 0 {
		t.Fatalf("expected 0 accumulated seconds, got %d", accum)
	}

	err := engine.ValidateDwell(10, 15, sessID)
	if err == nil {
		t.Fatalf("expected DwellError for 0-heartbeat session, got nil")
	}
}

func TestDwell_SufficientHeartbeatSessionAccepted(t *testing.T) {
	engine := NewEngine()
	sessID := "sess-valid"

	// Record 10,000ms across 4 heartbeats (4 x 2500ms = 10,000ms = 10s)
	for i := 0; i < 4; i++ {
		_, _, _, err := engine.RecordHeartbeat(sessID, "dec-1", "user-1", 2500, true)
		if err != nil {
			t.Fatalf("unexpected heartbeat error: %v", err)
		}
	}

	err := engine.ValidateDwell(10, 15, sessID)
	if err != nil {
		t.Fatalf("expected valid dwell, got error: %v", err)
	}
}
