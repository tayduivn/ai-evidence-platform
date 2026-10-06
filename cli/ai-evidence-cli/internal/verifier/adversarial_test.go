package verifier

import (
	"archive/zip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/canonical"
)

// Helper to copy entry map for isolated mutation
func copyEntries(src map[string][]byte) map[string][]byte {
	dst := make(map[string][]byte, len(src))
	for k, v := range src {
		cpy := make([]byte, len(v))
		copy(cpy, v)
		dst[k] = cpy
	}
	return dst
}

// Helper to read all entries from a zip archive
func readAllZipEntries(zipPath string) (map[string][]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	entries := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		entries[f.Name] = data
	}
	return entries, nil
}

// Helper to create a zip file from entry map
func buildZipFromEntries(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "pack.zip")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create entry %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("failed to write data for %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return outPath
}

// Helper to recalculate manifest.json for entries
func updateManifestForEntries(entries map[string][]byte, decisionID string, rootHash string) error {
	manifestFiles := make(map[string]PackFileMetadata)
	for name, data := range entries {
		if name == "manifest.json" {
			continue
		}
		manifestFiles[name] = PackFileMetadata{
			SHA256: sha256Hex(data),
			Size:   int64(len(data)),
		}
	}
	manifest := EvidencePackManifest{
		Version:    "1.0",
		DecisionID: decisionID,
		CreatedAt:  "2026-10-05T10:30:00Z",
		RootHash:   rootHash,
		Files:      manifestFiles,
	}
	manifestBytes, err := canonical.Marshal(manifest)
	if err != nil {
		return err
	}
	entries["manifest.json"] = manifestBytes
	return nil
}

// Helper to load PKCS8 RSA private key
func loadRSAPrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}

// Helper to sign payload with RSA-SHA256 PKCS1v15
func signPayloadRSA(privKey *rsa.PrivateKey, payload map[string]any) (string, error) {
	canonBytes, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256(canonBytes)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sigBytes), nil
}

// -------------------------------------------------------------
// 1. Challenge Against Zip Slip Attack
// -------------------------------------------------------------
func TestAdversarial_ZipSlip_PathTraversal(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readAllZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	traversalVectors := []struct {
		name        string
		entryPath   string
		expectError string
	}{
		{
			name:        "Classic unix double dot traversal",
			entryPath:   "../../evil.txt",
			expectError: "Zip slip detected in entry: ../../evil.txt",
		},
		{
			name:        "Single dot dot prefix",
			entryPath:   "../evil.txt",
			expectError: "Zip slip detected in entry: ../evil.txt",
		},
		{
			name:        "Deep traversal sequence",
			entryPath:   "../../../../etc/shadow",
			expectError: "Zip slip detected in entry: ../../../../etc/shadow",
		},
		{
			name:        "Mid-path traversal escaping parent",
			entryPath:   "subfolder/../../escaped.txt",
			expectError: "Zip slip detected in entry: subfolder/../../escaped.txt",
		},
		{
			name:        "Root slash absolute traversal",
			entryPath:   "/root/backdoor.sh",
			expectError: "Zip slip detected in entry: /root/backdoor.sh",
		},
		{
			name:        "Windows backslash traversal",
			entryPath:   "..\\..\\evil.txt",
			expectError: "Zip slip detected in entry: ..\\..\\evil.txt",
		},
	}

	for _, tc := range traversalVectors {
		t.Run(tc.name, func(t *testing.T) {
			entries := copyEntries(baseEntries)
			entries[tc.entryPath] = []byte("MALICIOUS PAYLOAD EXPLOIT TEST")

			packPath := buildZipFromEntries(t, entries)
			report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
			if err != nil {
				t.Fatalf("unexpected engine error: %v", err)
			}
			if report.ExitCode != ExitGeneralFail {
				t.Errorf("expected ExitGeneralFail (%d), got %d", ExitGeneralFail, report.ExitCode)
			}
			if report.Status != "FAILED" {
				t.Errorf("expected status FAILED, got %s", report.Status)
			}
			if !strings.Contains(report.Error, "Zip slip detected") {
				t.Errorf("expected Zip slip error message, got: %s", report.Error)
			}
		})
	}
}

// -------------------------------------------------------------
// 2. Challenge Against Single-Bit Payload / Signature Tampering
// -------------------------------------------------------------
func TestAdversarial_SingleBitTampering_DeterministicExitCodes(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readAllZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	var baseManifest EvidencePackManifest
	if err := json.Unmarshal(baseEntries["manifest.json"], &baseManifest); err != nil {
		t.Fatalf("failed to parse base manifest: %v", err)
	}

	// 2.1 Tamper manifest.json -> Exit 1 (ExitManifestFail)
	t.Run("Tamper_manifest_json_SyntaxBitFlip_TriggersExit1", func(t *testing.T) {
		entries := copyEntries(baseEntries)
		// Flip byte 0 of manifest.json to break JSON syntax
		entries["manifest.json"][0] ^= 0x01

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitManifestFail {
			t.Errorf("expected ExitManifestFail (1), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if report.Status != "FAILED" {
			t.Errorf("expected status FAILED, got %s", report.Status)
		}
	})

	t.Run("Tamper_manifest_json_HashField_TriggersExit1", func(t *testing.T) {
		entries := copyEntries(baseEntries)
		var manifest EvidencePackManifest
		if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
			t.Fatalf("failed to unmarshal manifest: %v", err)
		}
		// Tamper the recorded sha256 of events.json in manifest
		meta := manifest.Files["events.json"]
		meta.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		manifest.Files["events.json"] = meta
		manifestBytes, _ := canonical.Marshal(manifest)
		entries["manifest.json"] = manifestBytes

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitManifestFail {
			t.Errorf("expected ExitManifestFail (1), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "Hash mismatch for events.json") {
			t.Errorf("expected Hash mismatch error, got: %s", report.Error)
		}
	})

	// 2.2 Tamper events.json -> Exit 1 (ExitManifestFail)
	t.Run("Tamper_events_json_BitFlip_TriggersExit1", func(t *testing.T) {
		entries := copyEntries(baseEntries)
		// Flip 1 bit in events.json without updating manifest
		entries["events.json"][30] ^= 0x01

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitManifestFail {
			t.Errorf("expected ExitManifestFail (1), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "Hash mismatch for events.json") {
			t.Errorf("expected hash mismatch for events.json, got: %s", report.Error)
		}
	})

	// 2.3 Tamper merkle_proof.json -> Exit 2 (ExitMerkleFail)
	t.Run("Tamper_merkle_proof_json_BitFlip_TriggersExit2", func(t *testing.T) {
		entries := copyEntries(baseEntries)
		var proof MerkleProofData
		if err := json.Unmarshal(entries["merkle_proof.json"], &proof); err != nil {
			t.Fatalf("failed to unmarshal merkle proof: %v", err)
		}

		// Mutate 1 character in RootHash
		rhBytes := []byte(proof.RootHash)
		if rhBytes[0] == 'f' {
			rhBytes[0] = 'e'
		} else {
			rhBytes[0] = 'f'
		}
		proof.RootHash = string(rhBytes)
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes

		// Recalculate manifest so manifest check passes, isolating Merkle layer failure
		if err := updateManifestForEntries(entries, baseManifest.DecisionID, proof.RootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitMerkleFail {
			t.Errorf("expected ExitMerkleFail (2), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "Merkle root mismatch") {
			t.Errorf("expected Merkle root mismatch error, got: %s", report.Error)
		}
	})

	// 2.4 Tamper signature_1.json -> Exit 3 (ExitSignatureFail)
	t.Run("Tamper_signature_1_json_BitFlip_TriggersExit3", func(t *testing.T) {
		entries := copyEntries(baseEntries)
		var sig SignatureRecord
		if err := json.Unmarshal(entries["signatures/signature_1.json"], &sig); err != nil {
			t.Fatalf("failed to unmarshal signature: %v", err)
		}

		// Mutate 1 hex character in SignatureHex
		shBytes := []byte(sig.SignatureHex)
		if shBytes[4] == 'a' {
			shBytes[4] = 'b'
		} else {
			shBytes[4] = 'a'
		}
		sig.SignatureHex = string(shBytes)
		sigBytes, _ := canonical.Marshal(sig)
		entries["signatures/signature_1.json"] = sigBytes

		// Recalculate manifest so manifest check passes, isolating Signature layer failure
		if err := updateManifestForEntries(entries, baseManifest.DecisionID, baseManifest.RootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitSignatureFail {
			t.Errorf("expected ExitSignatureFail (3), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "Signature verification failed") {
			t.Errorf("expected signature verification failure, got: %s", report.Error)
		}
	})

	// 2.5 Tamper signer_1.pem -> Exit 4 (ExitCertFail)
	t.Run("Tamper_signer_1_pem_BitFlip_TriggersExit4", func(t *testing.T) {
		entries := copyEntries(baseEntries)

		// Mutate 1 byte inside base64 certificate content
		certStr := string(entries["certs/signer_1.pem"])
		lines := strings.Split(certStr, "\n")
		if len(lines) > 2 {
			// Alter 1 character in the second line of base64
			lineRunes := []rune(lines[1])
			if lineRunes[0] == 'M' {
				lineRunes[0] = 'N'
			} else {
				lineRunes[0] = 'M'
			}
			lines[1] = string(lineRunes)
			entries["certs/signer_1.pem"] = []byte(strings.Join(lines, "\n"))
		}

		// Recalculate manifest so manifest check passes, isolating Certificate layer failure
		if err := updateManifestForEntries(entries, baseManifest.DecisionID, baseManifest.RootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitCertFail {
			t.Errorf("expected ExitCertFail (4), got %d (err: %s)", report.ExitCode, report.Error)
		}
		errLower := strings.ToLower(report.Error)
		if !strings.Contains(errLower, "certificate") && !strings.Contains(errLower, "untrusted") {
			t.Errorf("expected Certificate error, got: %s", report.Error)
		}
	})
}

// -------------------------------------------------------------
// 3. Challenge Against Policy Bypass Attempts
// -------------------------------------------------------------
func TestAdversarial_PolicyBypass_CreatorSelfApproval(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readAllZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	// Subcase 3.1.A: Creator self-approval by Approver 1 ("approver-user-01")
	t.Run("CreatorSelfApproval_Approver1_FailsExit5", func(t *testing.T) {
		entries := copyEntries(baseEntries)

		var events []map[string]any
		if err := json.Unmarshal(entries["events.json"], &events); err != nil {
			t.Fatalf("failed to parse events: %v", err)
		}

		// Set creator_id matching Approver 1
		events[0]["creator_id"] = "approver-user-01"
		eventsBytes, _ := canonical.Marshal(events)
		entries["events.json"] = eventsBytes

		// Recalculate Merkle proof for updated events
		firstEventCanon, _ := canonical.Marshal(events[0])
		leafHash := sha256Hex(firstEventCanon)
		rootHash := sha256Hex([]byte(leafHash + leafHash))

		var proof MerkleProofData
		json.Unmarshal(entries["merkle_proof.json"], &proof)
		proof.LeafHash = leafHash
		proof.RootHash = rootHash
		proof.AuditPath = []string{leafHash}
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes

		// Update manifest so all hashes pass
		var manifest EvidencePackManifest
		json.Unmarshal(entries["manifest.json"], &manifest)
		if err := updateManifestForEntries(entries, manifest.DecisionID, rootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitPolicyFail {
			t.Errorf("expected ExitPolicyFail (5), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "creator cannot approve own decision") {
			t.Errorf("expected creator cannot approve own decision, got: %s", report.Error)
		}
	})

	// Subcase 3.1.B: Creator self-approval by Approver 2 ("approver-user-02")
	t.Run("CreatorSelfApproval_Approver2_FailsExit5", func(t *testing.T) {
		entries := copyEntries(baseEntries)

		var events []map[string]any
		if err := json.Unmarshal(entries["events.json"], &events); err != nil {
			t.Fatalf("failed to parse events: %v", err)
		}

		// Set creator_id matching Approver 2
		events[0]["creator_id"] = "approver-user-02"
		eventsBytes, _ := canonical.Marshal(events)
		entries["events.json"] = eventsBytes

		// Recalculate Merkle proof
		firstEventCanon, _ := canonical.Marshal(events[0])
		leafHash := sha256Hex(firstEventCanon)
		rootHash := sha256Hex([]byte(leafHash + leafHash))

		var proof MerkleProofData
		json.Unmarshal(entries["merkle_proof.json"], &proof)
		proof.LeafHash = leafHash
		proof.RootHash = rootHash
		proof.AuditPath = []string{leafHash}
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes

		var manifest EvidencePackManifest
		json.Unmarshal(entries["manifest.json"], &manifest)
		if err := updateManifestForEntries(entries, manifest.DecisionID, rootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitPolicyFail {
			t.Errorf("expected ExitPolicyFail (5), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "creator cannot approve own decision") {
			t.Errorf("expected creator cannot approve own decision, got: %s", report.Error)
		}
	})

	// Subcase 3.1.C: Separate creator ("ml-engine-system") passes policy check
	t.Run("DistinctCreator_PassesPolicy_Exit0", func(t *testing.T) {
		entries := copyEntries(baseEntries)

		var events []map[string]any
		if err := json.Unmarshal(entries["events.json"], &events); err != nil {
			t.Fatalf("failed to parse events: %v", err)
		}

		// Set creator_id distinct from approvers
		events[0]["creator_id"] = "ml-credit-scoring-model"
		eventsBytes, _ := canonical.Marshal(events)
		entries["events.json"] = eventsBytes

		firstEventCanon, _ := canonical.Marshal(events[0])
		leafHash := sha256Hex(firstEventCanon)
		rootHash := sha256Hex([]byte(leafHash + leafHash))

		var proof MerkleProofData
		json.Unmarshal(entries["merkle_proof.json"], &proof)
		proof.LeafHash = leafHash
		proof.RootHash = rootHash
		proof.AuditPath = []string{leafHash}
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes

		var manifest EvidencePackManifest
		json.Unmarshal(entries["manifest.json"], &manifest)
		if err := updateManifestForEntries(entries, manifest.DecisionID, rootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}

		packPath := buildZipFromEntries(t, entries)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitSuccess {
			t.Errorf("expected ExitSuccess (0), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if report.Message != "VERIFICATION_SUCCESS" {
			t.Errorf("expected VERIFICATION_SUCCESS, got: %s", report.Message)
		}
	})
}

func TestAdversarial_PolicyBypass_SameApproverFourEyes(t *testing.T) {
	// Directly verify policy_violation_pack.zip fixture and dynamic same-approver packs
	packPath := filepath.Join(fixturesDir(t), "policy_violation_pack.zip")
	report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ExitCode != ExitPolicyFail {
		t.Errorf("expected ExitPolicyFail (5), got %d", report.ExitCode)
	}
	if !strings.Contains(report.Error, "4-Eyes principle violated: duplicate approver detected") {
		t.Errorf("expected duplicate approver detected, got: %s", report.Error)
	}
}

func TestAdversarial_PolicyBypass_DwellTimeBoundary(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readAllZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	certsDir, err := filepath.Abs("../../../../tests/fixtures/certs")
	if err != nil {
		t.Fatalf("failed to resolve certs dir: %v", err)
	}

	key1Bytes, err := os.ReadFile(filepath.Join(certsDir, "signer_1.key"))
	if err != nil {
		t.Fatalf("failed to read signer_1.key: %v", err)
	}
	privKey1, err := loadRSAPrivateKey(key1Bytes)
	if err != nil {
		t.Fatalf("failed to parse signer_1 private key: %v", err)
	}

	var baseManifest EvidencePackManifest
	json.Unmarshal(baseEntries["manifest.json"], &baseManifest)

	// Helper to craft pack with specific dwell time for approver 1
	craftPackWithDwell := func(t *testing.T, dwellSeconds int) string {
		entries := copyEntries(baseEntries)

		var sig1 SignatureRecord
		json.Unmarshal(entries["signatures/signature_1.json"], &sig1)

		sig1.SignedPayload["dwell_time_seconds"] = dwellSeconds
		newSigHex, err := signPayloadRSA(privKey1, sig1.SignedPayload)
		if err != nil {
			t.Fatalf("failed to sign payload: %v", err)
		}
		sig1.SignatureHex = newSigHex
		sig1Bytes, _ := canonical.Marshal(sig1)
		entries["signatures/signature_1.json"] = sig1Bytes

		if err := updateManifestForEntries(entries, baseManifest.DecisionID, baseManifest.RootHash); err != nil {
			t.Fatalf("failed to update manifest: %v", err)
		}
		return buildZipFromEntries(t, entries)
	}

	// 3.3.A: Dwell 9s with --min-dwell 10 MUST fail with Exit 5
	t.Run("Dwell_9s_MinDwell_10s_FailsExit5", func(t *testing.T) {
		packPath := craftPackWithDwell(t, 9)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitPolicyFail {
			t.Errorf("expected ExitPolicyFail (5), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if !strings.Contains(report.Error, "Approver dwell time 9s < minimum 10s") {
			t.Errorf("expected dwell time 9s < minimum 10s, got: %s", report.Error)
		}
	})

	// 3.3.B: Dwell 10s with --min-dwell 10 MUST pass with Exit 0
	t.Run("Dwell_10s_MinDwell_10s_PassesExit0", func(t *testing.T) {
		packPath := craftPackWithDwell(t, 10)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitSuccess {
			t.Errorf("expected ExitSuccess (0), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if report.Message != "VERIFICATION_SUCCESS" {
			t.Errorf("expected VERIFICATION_SUCCESS, got: %s", report.Message)
		}
	})

	// 3.3.C: Dwell 11s with --min-dwell 10 MUST pass with Exit 0
	t.Run("Dwell_11s_MinDwell_10s_PassesExit0", func(t *testing.T) {
		packPath := craftPackWithDwell(t, 11)
		report, err := Verify(packPath, VerifyOptions{MinDwellSeconds: 10})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.ExitCode != ExitSuccess {
			t.Errorf("expected ExitSuccess (0), got %d (err: %s)", report.ExitCode, report.Error)
		}
		if report.Message != "VERIFICATION_SUCCESS" {
			t.Errorf("expected VERIFICATION_SUCCESS, got: %s", report.Message)
		}
	})
}
