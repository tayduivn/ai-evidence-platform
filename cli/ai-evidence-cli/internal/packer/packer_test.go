package packer

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
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/canonical"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

func generateTestCertificates(t *testing.T) ([]byte, []byte, *rsa.PrivateKey) {
	// Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"AI Evidence Corp"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Signer Cert
	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signer key: %v", err)
	}
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Signer 1",
			Organization: []string{"AI Evidence Corp"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, rootTemplate, &signerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create signer cert: %v", err)
	}
	signerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerDER})

	return rootPEM, signerPEM, signerKey
}

func TestPacker_DeterministicByteGeneration(t *testing.T) {
	rootPEM, signerPEM, signerKey := generateTestCertificates(t)

	decisionID := "test-det-001"
	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "credit-model-v1",
		"decision":           "APPROVE",
		"status":             "APPROVED",
		"output_payload":     "Approved 100M",
		"dwell_time_seconds": 15,
	}

	payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "approver-01",
		"action":             "APPROVE",
		"dwell_time_seconds": 15,
		"timestamp":          "2026-10-05T12:00:00Z",
	}
	payloadBytes, err := canonical.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	hashed := sha256.Sum256(payloadBytes)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, signerKey, 0, hashed[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	sigRecord := verifier.SignatureRecord{
		SignerType:    "internal",
		ApproverID:    "approver-01",
		SignedPayload: payload,
		SignatureHex:  hex.EncodeToString(sigBytes),
		Algorithm:     "SHA256withRSA",
	}

	fixedTime := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	inputs := &PackInputs{
		DecisionID:  decisionID,
		CreatedAt:   fixedTime,
		Events:      []any{event},
		Signatures:  []verifier.SignatureRecord{sigRecord},
		SignerCerts: [][]byte{signerPEM},
		RootCACert:  rootPEM,
		RFC3161TSR:  []byte("MOCK_RFC3161_DER_TST_TOKEN"),
	}

	var buf1, buf2 bytes.Buffer
	ctx := context.Background()

	_, err = BuildPack(ctx, inputs, &buf1)
	if err != nil {
		t.Fatalf("BuildPack 1 failed: %v", err)
	}

	_, err = BuildPack(ctx, inputs, &buf2)
	if err != nil {
		t.Fatalf("BuildPack 2 failed: %v", err)
	}

	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Errorf("BuildPack is not deterministic! Output bytes differ.")
	}
}

func TestPacker_BuildAndVerifyRoundTrip(t *testing.T) {
	rootPEM, signerPEM, signerKey := generateTestCertificates(t)

	tmpDir := t.TempDir()
	outZip := filepath.Join(tmpDir, "roundtrip_pack.zip")

	decisionID := "test-roundtrip-001"
	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "credit-model-v1",
		"decision":           "APPROVE",
		"status":             "APPROVED",
		"output_payload":     "Approved 500M",
		"dwell_time_seconds": 15,
	}

	payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "auditor-01",
		"action":             "APPROVE",
		"dwell_time_seconds": 15,
		"timestamp":          "2026-10-05T14:00:00Z",
	}
	payloadBytes, err := canonical.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	hashed := sha256.Sum256(payloadBytes)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, signerKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	sigRecord := verifier.SignatureRecord{
		SignerType:    "internal",
		ApproverID:    "auditor-01",
		SignedPayload: payload,
		SignatureHex:  hex.EncodeToString(sigBytes),
		Algorithm:     "SHA256withRSA",
	}

	inputs := &PackInputs{
		DecisionID:  decisionID,
		CreatedAt:   time.Now().UTC(),
		Events:      []any{event},
		Signatures:  []verifier.SignatureRecord{sigRecord},
		SignerCerts: [][]byte{signerPEM},
		RootCACert:  rootPEM,
	}

	ctx := context.Background()
	manifest, err := BuildPackToFile(ctx, inputs, outZip)
	if err != nil {
		t.Fatalf("BuildPackToFile failed: %v", err)
	}
	if manifest.DecisionID != decisionID {
		t.Errorf("expected decision_id %s, got %s", decisionID, manifest.DecisionID)
	}

	// Verify using Verifier engine
	report, err := verifier.Verify(outZip, verifier.VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("verifier error: %v", err)
	}
	if report.ExitCode != verifier.ExitSuccess {
		t.Errorf("expected ExitSuccess (0), got %d: %s", report.ExitCode, report.Error)
	}
	if report.Message != "VERIFICATION_SUCCESS" {
		t.Errorf("expected VERIFICATION_SUCCESS, got %s", report.Message)
	}
}

func TestPacker_PackDirectory(t *testing.T) {
	rootPEM, signerPEM, signerKey := generateTestCertificates(t)

	tmpDir := t.TempDir()
	stageDir := filepath.Join(tmpDir, "staged")
	if err := os.MkdirAll(filepath.Join(stageDir, "signatures"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stageDir, "certs"), 0755); err != nil {
		t.Fatal(err)
	}

	decisionID := "test-staged-001"
	event := map[string]any{
		"event_id":           decisionID,
		"ai_system_id":       "risk-model-v2",
		"decision":           "APPROVE",
		"status":             "APPROVED",
		"output_payload":     "Approved",
		"dwell_time_seconds": 20,
	}
	eventCanon, _ := canonical.Marshal(event)
	eventsJSON, _ := canonical.Marshal([]any{event})
	os.WriteFile(filepath.Join(stageDir, "events.json"), eventsJSON, 0644)

	leafHash := hex.EncodeToString(func() []byte { h := sha256.Sum256(eventCanon); return h[:] }())
	rootHash := hex.EncodeToString(func() []byte { h := sha256.Sum256([]byte(leafHash + leafHash)); return h[:] }())

	proof := verifier.MerkleProofData{
		RootHash:    rootHash,
		LeafHash:    leafHash,
		Index:       0,
		TotalLeaves: 1,
		AuditPath:   []string{leafHash},
	}
	proofJSON, _ := canonical.Marshal(proof)
	os.WriteFile(filepath.Join(stageDir, "merkle_proof.json"), proofJSON, 0644)

	payload := map[string]any{
		"decision_id":        decisionID,
		"approver_id":        "risk-officer-01",
		"action":             "APPROVE",
		"dwell_time_seconds": 20,
		"timestamp":          "2026-10-05T15:00:00Z",
	}
	payloadBytes, _ := canonical.Marshal(payload)
	hashed := sha256.Sum256(payloadBytes)
	sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, signerKey, crypto.SHA256, hashed[:])

	sigRecord := verifier.SignatureRecord{
		SignerType:    "internal",
		ApproverID:    "risk-officer-01",
		SignedPayload: payload,
		SignatureHex:  hex.EncodeToString(sigBytes),
		Algorithm:     "SHA256withRSA",
	}
	sigJSON, _ := canonical.Marshal(sigRecord)
	os.WriteFile(filepath.Join(stageDir, "signatures", "signature_1.json"), sigJSON, 0644)

	os.WriteFile(filepath.Join(stageDir, "certs", "signer_1.pem"), signerPEM, 0644)
	os.WriteFile(filepath.Join(stageDir, "certs", "root_ca.pem"), rootPEM, 0644)

	outZip := filepath.Join(tmpDir, "staged_pack.zip")
	ctx := context.Background()
	_, err := PackDirectory(ctx, stageDir, outZip)
	if err != nil {
		t.Fatalf("PackDirectory failed: %v", err)
	}

	report, err := verifier.Verify(outZip, verifier.VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("verifier error: %v", err)
	}
	if report.ExitCode != verifier.ExitSuccess {
		t.Errorf("expected ExitSuccess (0), got %d: %s", report.ExitCode, report.Error)
	}
}
