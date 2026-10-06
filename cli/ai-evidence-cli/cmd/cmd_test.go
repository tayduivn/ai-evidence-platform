package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

func fixturesDir(t *testing.T) string {
	abs, err := filepath.Abs("../../../tests/fixtures/evidence_packs")
	if err != nil {
		t.Fatalf("failed to resolve fixtures directory: %v", err)
	}
	return abs
}

func TestCLI_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "ai-evidence-cli") {
		t.Errorf("expected help output to contain ai-evidence-cli")
	}
}

func TestCLI_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "ai-evidence-cli v1.0.0") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestCLI_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{}, &stdout, &stderr)
	if code != int(verifier.ExitGeneralFail) {
		t.Errorf("expected exit code %d, got %d", verifier.ExitGeneralFail, code)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"unknown_foo"}, &stdout, &stderr)
	if code != int(verifier.ExitGeneralFail) {
		t.Errorf("expected exit code %d, got %d", verifier.ExitGeneralFail, code)
	}
}

func TestCLI_VerifyValidPack(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	if out != "VERIFICATION_SUCCESS" {
		t.Errorf("expected VERIFICATION_SUCCESS, got: %s", out)
	}
}

func TestCLI_VerifyValidPack_JSON(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	var report verifier.VerificationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON report: %v", err)
	}
	if report.Status != "SUCCESS" || report.ExitCode != 0 {
		t.Errorf("expected SUCCESS and code 0, got %s and %d", report.Status, report.ExitCode)
	}
}

func TestCLI_VerifyTamperedManifest(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "tampered_manifest.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Hash mismatch") {
		t.Errorf("expected Hash mismatch in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyTamperedMerkle(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "tampered_merkle.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Merkle root mismatch") {
		t.Errorf("expected Merkle root mismatch in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyInvalidSignature(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "invalid_signature.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("expected exit code 3, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Signature verification failed") {
		t.Errorf("expected Signature verification failed in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyUntrustedCert(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "untrusted_cert.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 4 {
		t.Errorf("expected exit code 4, got %d", code)
	}
	if !strings.Contains(stdout.String(), "untrusted or not signed by Root CA") {
		t.Errorf("expected untrusted in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyPolicyViolation(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "policy_violation_pack.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 5 {
		t.Errorf("expected exit code 5, got %d", code)
	}
	if !strings.Contains(stdout.String(), "duplicate approver") {
		t.Errorf("expected duplicate approver in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyDwellTimeFlag(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath, "--min-dwell", "100"}, &stdout, &stderr)
	if code != 5 {
		t.Errorf("expected exit code 5, got %d", code)
	}
	if !strings.Contains(stdout.String(), "dwell time 15s < minimum 100s") {
		t.Errorf("expected dwell time in output, got: %s", stdout.String())
	}
}

func TestCLI_VerifyCorruptArchive(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "corrupt_archive.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != 6 {
		t.Errorf("expected exit code 6, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Corrupt or invalid zip archive") {
		t.Errorf("expected Corrupt or invalid zip in output, got: %s", stdout.String())
	}
}

func TestCLI_Inspect(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"inspect", packPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "EVIDENCE PACK INSPECTION") {
		t.Errorf("expected inspection header, got: %s", out)
	}
	if !strings.Contains(out, "credit-advisor-v1") {
		t.Errorf("expected credit-advisor-v1, got: %s", out)
	}
}
