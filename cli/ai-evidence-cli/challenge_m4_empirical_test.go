package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/canonical"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/inspector"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/packer"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

// Helper to generate CA and signers
func setupTestPKI(t *testing.T) (rootPEM []byte, signer1PEM []byte, signer1Key *rsa.PrivateKey, signer2PEM []byte, signer2Key *rsa.PrivateKey) {
	// Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Empirical Root CA",
			Organization: []string{"Empirical Test Corp"},
		},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Signer 1
	signer1Key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signer1 key: %v", err)
	}
	s1Tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   "Empirical Approver Alpha",
			Organization: []string{"Empirical Test Corp"},
		},
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	}
	s1DER, err := x509.CreateCertificate(rand.Reader, s1Tmpl, rootTmpl, &signer1Key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create signer 1 cert: %v", err)
	}
	signer1PEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s1DER})

	// Signer 2
	signer2Key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signer2 key: %v", err)
	}
	s2Tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject: pkix.Name{
			CommonName:   "Empirical Approver Beta",
			Organization: []string{"Empirical Test Corp"},
		},
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	}
	s2DER, err := x509.CreateCertificate(rand.Reader, s2Tmpl, rootTmpl, &signer2Key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create signer 2 cert: %v", err)
	}
	signer2PEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s2DER})

	return
}

func signPayloadRSA(t *testing.T, payload map[string]any, key *rsa.PrivateKey) string {
	b, err := canonical.Marshal(payload)
	if err != nil {
		t.Fatalf("canonical marshal failed: %v", err)
	}
	hashed := sha256.Sum256(b)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	return hex.EncodeToString(sig)
}

// 1. EMPIRICAL CHALLENGE: Deterministic ZIP Packing across different execution times
func TestEmpirical_PackagingDeterminism(t *testing.T) {
	rootPEM, s1PEM, s1Key, s2PEM, s2Key := setupTestPKI(t)

	decisionID := "empirical-det-dec-9988"
	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "credit-risk-v3",
		"system_type":        "llm",
		"model_version":      "claude-3-5-sonnet",
		"decision":           "APPROVE_LOAN_500M",
		"status":             "APPROVED",
		"output_payload":     "Loan approved",
		"dwell_time_seconds": 25,
		"timestamp":          "2026-10-05T12:00:00Z",
	}

	sig1Payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "approver-alpha",
		"action":             "APPROVE",
		"dwell_time_seconds": 25,
		"timestamp":          "2026-10-05T12:05:00Z",
	}
	sig1Hex := signPayloadRSA(t, sig1Payload, s1Key)

	sig2Payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "approver-beta",
		"action":             "APPROVE",
		"dwell_time_seconds": 30,
		"timestamp":          "2026-10-05T12:06:00Z",
	}
	sig2Hex := signPayloadRSA(t, sig2Payload, s2Key)

	sigRecords := []verifier.SignatureRecord{
		{
			SignerType:    "internal",
			ApproverID:    "approver-alpha",
			SignedPayload: sig1Payload,
			SignatureHex:  sig1Hex,
			Algorithm:     "SHA256withRSA",
		},
		{
			SignerType:    "internal",
			ApproverID:    "approver-beta",
			SignedPayload: sig2Payload,
			SignatureHex:  sig2Hex,
			Algorithm:     "SHA256withRSA",
		},
	}

	normalizedCreatedAt := time.Date(2026, 10, 5, 12, 10, 0, 0, time.UTC)

	inputs := &packer.PackInputs{
		DecisionID:  decisionID,
		CreatedAt:   normalizedCreatedAt,
		Events:      []any{event},
		Signatures:  sigRecords,
		SignerCerts: [][]byte{s1PEM, s2PEM},
		RootCACert:  rootPEM,
		RFC3161TSR:  []byte("MOCK_RFC3161_TST_TOKEN_EMPIRICAL"),
	}

	ctx := context.Background()

	// Run 1: First packaging
	var buf1 bytes.Buffer
	m1, err := packer.BuildPack(ctx, inputs, &buf1)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	hash1 := sha256.Sum256(buf1.Bytes())
	t.Logf("Run 1 SHA-256: %s (size: %d bytes)", hex.EncodeToString(hash1[:]), buf1.Len())

	// Explicitly delay execution to advance wall clock time
	time.Sleep(1200 * time.Millisecond)

	// Run 2: Second packaging at a different time
	var buf2 bytes.Buffer
	m2, err := packer.BuildPack(ctx, inputs, &buf2)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	hash2 := sha256.Sum256(buf2.Bytes())
	t.Logf("Run 2 SHA-256: %s (size: %d bytes)", hex.EncodeToString(hash2[:]), buf2.Len())

	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatalf("DETERMINISM FAILED: packaging same inputs at different times produced non-identical bytes!\nRun 1: %s\nRun 2: %s",
			hex.EncodeToString(hash1[:]), hex.EncodeToString(hash2[:]))
	}

	if hash1 != hash2 {
		t.Fatalf("DETERMINISM FAILED: SHA-256 mismatch: %x != %x", hash1, hash2)
	}

	if m1.RootHash != m2.RootHash {
		t.Fatalf("Manifest RootHash mismatch: %s != %s", m1.RootHash, m2.RootHash)
	}

	// Stress loop: 25 iterations with randomized timing
	for i := 0; i < 25; i++ {
		var loopBuf bytes.Buffer
		_, err := packer.BuildPack(ctx, inputs, &loopBuf)
		if err != nil {
			t.Fatalf("loop %d failed: %v", i, err)
		}
		loopHash := sha256.Sum256(loopBuf.Bytes())
		if loopHash != hash1 {
			t.Fatalf("loop %d determinism broken: hash %s != %s", i, hex.EncodeToString(loopHash[:]), hex.EncodeToString(hash1[:]))
		}
	}
	t.Log("PASSED: 25/25 packaging iterations produced bit-for-bit identical ZIP archives!")
}

// 2. EMPIRICAL CHALLENGE: Full Packaging Roundtrip
func TestEmpirical_PackagingRoundtrip(t *testing.T) {
	rootPEM, s1PEM, s1Key, s2PEM, s2Key := setupTestPKI(t)
	tmpDir := t.TempDir()
	outZipPath := filepath.Join(tmpDir, "empirical_roundtrip.zip")

	decisionID := "empirical-rt-dec-1122"
	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "medical-diagnostic-ai",
		"system_type":        "llm",
		"model_version":      "gpt-4o",
		"decision":           "APPROVE_TREATMENT_PLAN",
		"status":             "APPROVED",
		"output_payload":     "Treatment approved by specialists",
		"dwell_time_seconds": 20,
		"timestamp":          "2026-10-05T13:00:00Z",
	}

	sig1Payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "dr-smith",
		"action":             "APPROVE",
		"dwell_time_seconds": 20,
		"timestamp":          "2026-10-05T13:05:00Z",
	}
	sig1Hex := signPayloadRSA(t, sig1Payload, s1Key)

	sig2Payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "dr-johnson",
		"action":             "APPROVE",
		"dwell_time_seconds": 25,
		"timestamp":          "2026-10-05T13:06:00Z",
	}
	sig2Hex := signPayloadRSA(t, sig2Payload, s2Key)

	inputs := &packer.PackInputs{
		DecisionID: decisionID,
		CreatedAt:  time.Now().UTC(),
		Events:     []any{event},
		Signatures: []verifier.SignatureRecord{
			{
				SignerType:    "internal",
				ApproverID:    "dr-smith",
				SignedPayload: sig1Payload,
				SignatureHex:  sig1Hex,
				Algorithm:     "SHA256withRSA",
			},
			{
				SignerType:    "internal",
				ApproverID:    "dr-johnson",
				SignedPayload: sig2Payload,
				SignatureHex:  sig2Hex,
				Algorithm:     "SHA256withRSA",
			},
		},
		SignerCerts: [][]byte{s1PEM, s2PEM},
		RootCACert:  rootPEM,
		RFC3161TSR:  []byte("MOCK_RFC3161_TOKEN"),
	}

	ctx := context.Background()
	manifest, err := packer.BuildPackToFile(ctx, inputs, outZipPath)
	if err != nil {
		t.Fatalf("BuildPackToFile failed: %v", err)
	}
	t.Logf("Generated pack: %s (Decision ID: %s, Files: %d)", outZipPath, manifest.DecisionID, len(manifest.Files))

	// Step 2a: Verify using in-process verifier
	report, err := verifier.Verify(outZipPath, verifier.VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("verifier unexpected error: %v", err)
	}
	if report.ExitCode != verifier.ExitSuccess {
		t.Fatalf("in-process verifier failed: ExitCode %d, Error: %s", report.ExitCode, report.Error)
	}
	if report.Message != "VERIFICATION_SUCCESS" {
		t.Fatalf("in-process verifier expected VERIFICATION_SUCCESS, got: %s", report.Message)
	}
	t.Log("PASSED: In-process verifier returned Exit 0 and VERIFICATION_SUCCESS")

	// Step 2b: Verify using ai-evidence-cli verify as real OS subprocess
	binPath := buildBinary(t)
	cmd := exec.Command(binPath, "verify", outZipPath)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("CLI subprocess verify failed: %v, output: %s", err, outStr)
	}
	if outStr != "VERIFICATION_SUCCESS" {
		t.Fatalf("CLI subprocess expected exact 'VERIFICATION_SUCCESS', got: %q", outStr)
	}
	t.Log("PASSED: Subprocess CLI verify returned Exit 0 and exact 'VERIFICATION_SUCCESS'")

	// Step 2c: Inspect newly built pack via subprocess inspect --json
	cmdInspect := exec.Command(binPath, "inspect", outZipPath, "--json")
	outInspect, err := cmdInspect.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI subprocess inspect failed: %v, output: %s", err, string(outInspect))
	}
	var inspReport inspector.InspectionReport
	if err := json.Unmarshal(outInspect, &inspReport); err != nil {
		t.Fatalf("inspect output is not valid JSON: %v", err)
	}
	if inspReport.DecisionID != decisionID {
		t.Errorf("inspect decision_id mismatch: %s != %s", inspReport.DecisionID, decisionID)
	}
	if len(inspReport.Approvers) != 2 {
		t.Errorf("inspect approvers length mismatch: %d != 2", len(inspReport.Approvers))
	}
	t.Log("PASSED: Subprocess CLI inspect accurately extracted fields from freshly generated pack!")
}

// 3. EMPIRICAL CHALLENGE: Subprocess CLI Execution Across All 7 Reference Fixtures
func TestEmpirical_SubprocessSevenFixtures(t *testing.T) {
	binPath := buildBinary(t)
	fDir := fixturesDir(t)

	fixtures := []struct {
		name         string
		filename     string
		expectedCode int
		expectedFrag string
	}{
		{
			name:         "Fixture 1: valid_pack.zip",
			filename:     "valid_pack.zip",
			expectedCode: 0,
			expectedFrag: "VERIFICATION_SUCCESS",
		},
		{
			name:         "Fixture 2: tampered_manifest.zip",
			filename:     "tampered_manifest.zip",
			expectedCode: 1,
			expectedFrag: "Hash mismatch",
		},
		{
			name:         "Fixture 3: tampered_merkle.zip",
			filename:     "tampered_merkle.zip",
			expectedCode: 2,
			expectedFrag: "Merkle root mismatch",
		},
		{
			name:         "Fixture 4: invalid_signature.zip",
			filename:     "invalid_signature.zip",
			expectedCode: 3,
			expectedFrag: "Signature verification failed",
		},
		{
			name:         "Fixture 5: untrusted_cert.zip",
			filename:     "untrusted_cert.zip",
			expectedCode: 4,
			expectedFrag: "untrusted or not signed by Root CA",
		},
		{
			name:         "Fixture 6: policy_violation_pack.zip",
			filename:     "policy_violation_pack.zip",
			expectedCode: 5,
			expectedFrag: "duplicate approver",
		},
		{
			name:         "Fixture 7: corrupt_archive.zip",
			filename:     "corrupt_archive.zip",
			expectedCode: 6,
			expectedFrag: "Corrupt or invalid zip archive",
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			targetPath := filepath.Join(fDir, fx.filename)
			cmd := exec.Command(binPath, "verify", targetPath)
			out, err := cmd.CombinedOutput()
			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("unexpected OS exec error: %v", err)
				}
			}

			if exitCode != fx.expectedCode {
				t.Fatalf("%s: expected exit code %d, got %d (output: %s)", fx.name, fx.expectedCode, exitCode, string(out))
			}
			if !strings.Contains(string(out), fx.expectedFrag) {
				t.Fatalf("%s: output missing expected fragment %q, got: %s", fx.name, fx.expectedFrag, string(out))
			}
			t.Logf("PASSED %s: Exit %d, Output contained %q", fx.name, exitCode, fx.expectedFrag)
		})
	}
}

// 4. EMPIRICAL CHALLENGE: Inspect Command Output Field Extraction Accuracy
func TestEmpirical_InspectFieldExtraction(t *testing.T) {
	binPath := buildBinary(t)
	fDir := fixturesDir(t)
	validPack := filepath.Join(fDir, "valid_pack.zip")

	// 4a. Plain text inspect
	cmdText := exec.Command(binPath, "inspect", validPack)
	outText, err := cmdText.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect text failed: %v", err)
	}
	textStr := string(outText)

	// Verbatim inspection assertions from valid_pack.zip
	assertions := []struct {
		desc string
		frag string
	}{
		{"Decision ID", "018f3a9e-4e89-7b21-9921-3a81289128aa"},
		{"Approver 1", "approver-user-01"},
		{"Approver 2", "approver-user-02"},
		{"Dwell Time 1", "15s"},
		{"Dwell Time 2", "20s"},
		{"Merkle Root", "49484a08375b65e4f5fba0acf1c66437ea61137a3a54b4dbe52240eeec60954d"},
		{"Cert Subject 1", "Nguyen Van Approver (Credit Lead)"},
		{"Cert Subject 2", "Tran Thi Risk Officer (4-Eyes Auditor)"},
	}

	for _, a := range assertions {
		if !strings.Contains(textStr, a.frag) {
			t.Errorf("inspect text output missing %s (%q):\n%s", a.desc, a.frag, textStr)
		}
	}

	// 4b. Structured JSON inspect
	cmdJSON := exec.Command(binPath, "inspect", validPack, "--json")
	outJSON, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}

	var rep inspector.InspectionReport
	if err := json.Unmarshal(outJSON, &rep); err != nil {
		t.Fatalf("failed to parse inspect JSON output: %v\nJSON:\n%s", err, string(outJSON))
	}

	if rep.DecisionID != "018f3a9e-4e89-7b21-9921-3a81289128aa" {
		t.Errorf("JSON DecisionID mismatch: expected 018f3a9e-4e89-7b21-9921-3a81289128aa, got %s", rep.DecisionID)
	}

	if len(rep.Approvers) != 2 {
		t.Fatalf("JSON Approvers count mismatch: expected 2, got %d", len(rep.Approvers))
	}

	// Approver 1
	app1 := rep.Approvers[0]
	if app1.ApproverID != "approver-user-01" {
		t.Errorf("Approver 1 ID mismatch: expected approver-user-01, got %s", app1.ApproverID)
	}
	if app1.DwellTimeSeconds != 15 {
		t.Errorf("Approver 1 DwellTime mismatch: expected 15, got %d", app1.DwellTimeSeconds)
	}
	if !strings.Contains(app1.CertSubject, "Nguyen Van Approver (Credit Lead)") {
		t.Errorf("Approver 1 CertSubject mismatch: expected 'Nguyen Van Approver (Credit Lead)', got %s", app1.CertSubject)
	}

	// Approver 2
	app2 := rep.Approvers[1]
	if app2.ApproverID != "approver-user-02" {
		t.Errorf("Approver 2 ID mismatch: expected approver-user-02, got %s", app2.ApproverID)
	}
	if app2.DwellTimeSeconds != 20 {
		t.Errorf("Approver 2 DwellTime mismatch: expected 20, got %d", app2.DwellTimeSeconds)
	}
	if !strings.Contains(app2.CertSubject, "Tran Thi Risk Officer (4-Eyes Auditor)") {
		t.Errorf("Approver 2 CertSubject mismatch: expected 'Tran Thi Risk Officer (4-Eyes Auditor)', got %s", app2.CertSubject)
	}

	// Merkle root
	if rep.MerkleRoot != "49484a08375b65e4f5fba0acf1c66437ea61137a3a54b4dbe52240eeec60954d" {
		t.Errorf("Merkle root mismatch: expected 49484a08375b65e4f5fba0acf1c66437ea61137a3a54b4dbe52240eeec60954d, got %s", rep.MerkleRoot)
	}

	t.Log("PASSED: Inspect text and JSON outputs accurately extract all forensic fields!")
}
