package inspector

import (
	"path/filepath"
	"strings"
	"testing"
)

func fixturesDir(t *testing.T) string {
	abs, err := filepath.Abs("../../../../tests/fixtures/evidence_packs")
	if err != nil {
		t.Fatalf("failed to resolve fixtures directory: %v", err)
	}
	return abs
}

func TestInspect_ValidPack(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	report, err := Inspect(packPath, InspectOptions{ShowPayloads: false})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.DecisionID != "018f3a9e-4e89-7b21-9921-3a81289128aa" {
		t.Errorf("expected decision_id 018f3a9e-4e89-7b21-9921-3a81289128aa, got %s", report.DecisionID)
	}
	if report.Status != "APPROVED" {
		t.Errorf("expected status APPROVED, got %s", report.Status)
	}
	if report.AISystemID != "credit-advisor-v1" {
		t.Errorf("expected ai_system_id credit-advisor-v1, got %s", report.AISystemID)
	}
	if len(report.Approvers) != 2 {
		t.Errorf("expected 2 approvers, got %d", len(report.Approvers))
	}
	if report.Approvers[0].ApproverID != "approver-user-01" {
		t.Errorf("expected approver-user-01, got %s", report.Approvers[0].ApproverID)
	}
	if report.Approvers[1].ApproverID != "approver-user-02" {
		t.Errorf("expected approver-user-02, got %s", report.Approvers[1].ApproverID)
	}
	if report.MerkleRoot == "" {
		t.Errorf("expected non-empty merkle root")
	}

	text := report.TextSummary(false)
	if !strings.Contains(text, "018f3a9e-4e89-7b21-9921-3a81289128aa") {
		t.Errorf("text missing decision ID")
	}
	if !strings.Contains(text, "credit-advisor-v1") {
		t.Errorf("text missing system ID")
	}
	if !strings.Contains(text, "4-Eyes Principle") {
		t.Errorf("text missing 4-Eyes Principle header")
	}
}

func TestInspect_NonExistentFile(t *testing.T) {
	_, err := Inspect("non_existent_file.zip", InspectOptions{})
	if err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}
