package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/packer"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

// Adversarial Test 1: CLI Flags, Root CA Override, and Dwell Boundaries
func TestAdversarial_FlagsAndOverrides(t *testing.T) {
	binPath := buildBinary(t)
	fDir := fixturesDir(t)
	validPack := filepath.Join(fDir, "valid_pack.zip")

	// 1a. --min-dwell 50 triggers Exit 5
	cmdDwell := exec.Command(binPath, "verify", validPack, "--min-dwell", "50")
	outDwell, err := cmdDwell.CombinedOutput()
	codeDwell := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			codeDwell = exitErr.ExitCode()
		}
	}
	if codeDwell != 5 {
		t.Fatalf("expected Exit 5 with --min-dwell 50, got %d: %s", codeDwell, string(outDwell))
	}
	if !strings.Contains(string(outDwell), "minimum 50s") {
		t.Errorf("output missing expected dwell message: %s", string(outDwell))
	}

	// 1b. Shorthand -d 50 also triggers Exit 5
	cmdDwellShort := exec.Command(binPath, "verify", validPack, "-d", "50")
	outDwellShort, err := cmdDwellShort.CombinedOutput()
	codeDwellShort := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			codeDwellShort = exitErr.ExitCode()
		}
	}
	if codeDwellShort != 5 {
		t.Fatalf("expected Exit 5 with -d 50, got %d: %s", codeDwellShort, string(outDwellShort))
	}

	// 1c. JSON output format: verify valid_pack.zip --json
	cmdJSON := exec.Command(binPath, "verify", validPack, "--json")
	outJSON, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("verify --json failed: %v", err)
	}
	var vReport verifier.VerificationReport
	if err := json.Unmarshal(outJSON, &vReport); err != nil {
		t.Fatalf("failed to parse verify JSON: %v\nOutput: %s", err, string(outJSON))
	}
	if vReport.ExitCode != 0 || vReport.Status != "SUCCESS" || vReport.Message != "VERIFICATION_SUCCESS" {
		t.Fatalf("unexpected JSON report: %+v", vReport)
	}

	// 1d. Verbose output format: verify valid_pack.zip --verbose
	cmdVerbose := exec.Command(binPath, "verify", validPack, "--verbose")
	outVerbose, err := cmdVerbose.CombinedOutput()
	if err != nil {
		t.Fatalf("verify --verbose failed: %v", err)
	}
	if !strings.Contains(string(outVerbose), "[OK]") {
		t.Errorf("verbose output missing [OK] markers:\n%s", string(outVerbose))
	}

	// 1e. Root CA override with untrusted foreign CA triggers Exit 4
	tmpDir := t.TempDir()
	foreignKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	foreignTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			CommonName: "Foreign Untrusted Attacker CA",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		IsCA:      true,
	}
	foreignDER, _ := x509.CreateCertificate(rand.Reader, foreignTmpl, foreignTmpl, &foreignKey.PublicKey, foreignKey)
	foreignPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignDER})
	foreignCAPath := filepath.Join(tmpDir, "foreign_ca.pem")
	os.WriteFile(foreignCAPath, foreignPEM, 0644)

	cmdOverride := exec.Command(binPath, "verify", validPack, "--root-ca", foreignCAPath)
	outOverride, err := cmdOverride.CombinedOutput()
	codeOverride := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			codeOverride = exitErr.ExitCode()
		}
	}
	if codeOverride != 4 {
		t.Fatalf("expected Exit 4 with foreign root CA override, got %d: %s", codeOverride, string(outOverride))
	}
	if !strings.Contains(string(outOverride), "untrusted or not signed by Root CA") {
		t.Errorf("output missing expected cert error message: %s", string(outOverride))
	}
}

// Adversarial Test 2: Zip Slip Injection
func TestAdversarial_ZipSlipExploit(t *testing.T) {
	binPath := buildBinary(t)
	tmpDir := t.TempDir()
	slipZipPath := filepath.Join(tmpDir, "zip_slip_attack.zip")

	// Create malicious ZIP containing a path traversal entry
	f, err := os.Create(slipZipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// Add evil entry
	w, err := zw.Create("../../evil_escaped_file.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("MALICIOUS PAYLOAD"))
	zw.Close()
	f.Close()

	cmd := exec.Command(binPath, "verify", slipZipPath)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}

	if code != 6 {
		t.Fatalf("expected Exit 6 for Zip Slip, got %d: %s", code, string(out))
	}
	if !strings.Contains(string(out), "Zip slip detected") {
		t.Errorf("expected 'Zip slip detected' message, got: %s", string(out))
	}
}

// Adversarial Test 3: Policy Violation: Creator Self-Approval
func TestAdversarial_CreatorSelfApprovalPolicy(t *testing.T) {
	rootPEM, s1PEM, s1Key, _, _ := setupTestPKI(t)
	tmpDir := t.TempDir()
	outZipPath := filepath.Join(tmpDir, "creator_self_approval.zip")

	decisionID := "dec-creator-self-001"
	creatorID := "user-alice"

	// Alice creates the event
	event := map[string]any{
		"event_id":           decisionID,
		"creator_id":         creatorID, // Alice is creator!
		"ai_system_id":       "credit-model",
		"decision":           "APPROVE",
		"status":             "APPROVED",
		"output_payload":     "Approved",
		"dwell_time_seconds": 15,
	}

	// Alice also signs as approver!
	sigPayload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        creatorID, // Alice attempts self-approval!
		"action":             "APPROVE",
		"dwell_time_seconds": 15,
		"timestamp":          "2026-10-05T12:00:00Z",
	}
	sigHex := signPayloadRSA(t, sigPayload, s1Key)

	inputs := &packer.PackInputs{
		DecisionID: decisionID,
		CreatedAt:  time.Now().UTC(),
		Events:     []any{event},
		Signatures: []verifier.SignatureRecord{
			{
				SignerType:    "internal",
				ApproverID:    creatorID,
				SignedPayload: sigPayload,
				SignatureHex:  sigHex,
				Algorithm:     "SHA256withRSA",
			},
		},
		SignerCerts: [][]byte{s1PEM},
		RootCACert:  rootPEM,
	}

	ctx := context.Background()
	_, err := packer.BuildPackToFile(ctx, inputs, outZipPath)
	if err != nil {
		t.Fatalf("BuildPackToFile failed: %v", err)
	}

	// Subprocess CLI verify
	binPath := buildBinary(t)
	cmd := exec.Command(binPath, "verify", outZipPath)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}

	if code != 5 {
		t.Fatalf("expected Exit 5 (Policy Fail) for creator self-approval, got %d: %s", code, string(out))
	}
	if !strings.Contains(string(out), "creator cannot approve own decision") {
		t.Errorf("output missing expected creator rejection message: %s", string(out))
	}
}

// Adversarial Test 4: Unicode and Vietnamese Character Fidelity in Packaging
func TestAdversarial_VietnameseUnicodeFidelity(t *testing.T) {
	rootPEM, s1PEM, s1Key, _, _ := setupTestPKI(t)
	tmpDir := t.TempDir()
	outZipPath := filepath.Join(tmpDir, "vietnamese_unicode.zip")

	decisionID := "dec-vn-unicode-8899"
	promptText := "Khach hang Nguyen Van Dat (CCCD: 001090012345), thu nhap 50.000.000 VND/thang"
	responseText := "He thong phe duyet han muc 1.000.000.000 VND."

	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "tro-ly-tin-dung-v1",
		"decision":           "PHE_DUYET_HAN_MUC",
		"input_payload":      promptText,
		"output_payload":     responseText,
		"input_masked":       promptText,
		"output_masked":      responseText,
		"dwell_time_seconds": 15,
	}

	sigPayload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "nguyen.van.kiem.toan",
		"action":             "PHE_DUYET",
		"dwell_time_seconds": 15,
		"timestamp":          "2026-10-05T12:00:00Z",
	}
	sigHex := signPayloadRSA(t, sigPayload, s1Key)

	inputs := &packer.PackInputs{
		DecisionID: decisionID,
		CreatedAt:  time.Now().UTC(),
		Events:     []any{event},
		Signatures: []verifier.SignatureRecord{
			{
				SignerType:    "internal",
				ApproverID:    "nguyen.van.kiem.toan",
				SignedPayload: sigPayload,
				SignatureHex:  sigHex,
				Algorithm:     "SHA256withRSA",
			},
		},
		SignerCerts: [][]byte{s1PEM},
		RootCACert:  rootPEM,
	}

	ctx := context.Background()
	_, err := packer.BuildPackToFile(ctx, inputs, outZipPath)
	if err != nil {
		t.Fatalf("BuildPackToFile failed: %v", err)
	}

	// Verify with CLI
	binPath := buildBinary(t)
	cmdVerify := exec.Command(binPath, "verify", outZipPath)
	outVerify, err := cmdVerify.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed on pack: %v, output: %s", err, string(outVerify))
	}
	if strings.TrimSpace(string(outVerify)) != "VERIFICATION_SUCCESS" {
		t.Fatalf("expected exact VERIFICATION_SUCCESS, got: %s", string(outVerify))
	}

	// Inspect with CLI
	cmdInspect := exec.Command(binPath, "inspect", outZipPath, "--json")
	outInspect, err := cmdInspect.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect failed on pack: %v", err)
	}
	if !strings.Contains(string(outInspect), "Nguyen Van Dat") {
		t.Errorf("inspect JSON output missing text:\n%s", string(outInspect))
	}
}