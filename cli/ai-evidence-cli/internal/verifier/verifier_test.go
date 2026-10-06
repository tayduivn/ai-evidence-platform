package verifier

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

func TestVerify_ValidPack(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitSuccess {
		t.Errorf("expected exit code %d, got %d (error: %s)", ExitSuccess, report.ExitCode, report.Error)
	}
	if report.Message != "VERIFICATION_SUCCESS" {
		t.Errorf("expected message VERIFICATION_SUCCESS, got %s", report.Message)
	}
	if report.Status != "SUCCESS" {
		t.Errorf("expected status SUCCESS, got %s", report.Status)
	}
}

func TestVerify_TamperedManifest(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "tampered_manifest.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitManifestFail {
		t.Errorf("expected exit code %d, got %d", ExitManifestFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "Hash mismatch") {
		t.Errorf("expected Hash mismatch in error, got: %s", report.Error)
	}
}

func TestVerify_TamperedMerkle(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "tampered_merkle.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitMerkleFail {
		t.Errorf("expected exit code %d, got %d", ExitMerkleFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "Merkle root mismatch") {
		t.Errorf("expected Merkle root mismatch in error, got: %s", report.Error)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "invalid_signature.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitSignatureFail {
		t.Errorf("expected exit code %d, got %d", ExitSignatureFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "Signature verification failed") {
		t.Errorf("expected Signature verification failed in error, got: %s", report.Error)
	}
}

func TestVerify_UntrustedCert(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "untrusted_cert.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitCertFail {
		t.Errorf("expected exit code %d, got %d", ExitCertFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "untrusted or not signed by Root CA") {
		t.Errorf("expected untrusted or not signed by Root CA in error, got: %s", report.Error)
	}
}

func TestVerify_PolicyViolation_DuplicateApprover(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "policy_violation_pack.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitPolicyFail {
		t.Errorf("expected exit code %d, got %d", ExitPolicyFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "duplicate approver") {
		t.Errorf("expected duplicate approver in error, got: %s", report.Error)
	}
}

func TestVerify_PolicyViolation_DwellTimeExceeded(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	// valid_pack has 15s and 20s dwell times; min-dwell 100 should fail on 15s
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitPolicyFail {
		t.Errorf("expected exit code %d, got %d", ExitPolicyFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "dwell time 15s < minimum 100s") {
		t.Errorf("expected dwell time 15s < minimum 100s in error, got: %s", report.Error)
	}
}

func TestVerify_CorruptArchive(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "corrupt_archive.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitGeneralFail {
		t.Errorf("expected exit code %d, got %d", ExitGeneralFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "Corrupt or invalid zip archive") {
		t.Errorf("expected Corrupt or invalid zip archive in error, got: %s", report.Error)
	}
}

func TestVerify_NonExistentFile(t *testing.T) {
	packPath := filepath.Join(fixturesDir(t), "non_existent_file_987654.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitGeneralFail {
		t.Errorf("expected exit code %d, got %d", ExitGeneralFail, report.ExitCode)
	}
	if !strings.Contains(report.Error, "not found") {
		t.Errorf("expected 'not found' in error, got: %s", report.Error)
	}
}
