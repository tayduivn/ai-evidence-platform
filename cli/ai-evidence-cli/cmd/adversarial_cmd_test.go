package cmd

import (
	"archive/zip"
	"bytes"
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
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

// Helper to copy entries map
func copyCmdEntries(src map[string][]byte) map[string][]byte {
	dst := make(map[string][]byte, len(src))
	for k, v := range src {
		cpy := make([]byte, len(v))
		copy(cpy, v)
		dst[k] = cpy
	}
	return dst
}

// Helper to read all entries from zip
func readCmdZipEntries(zipPath string) (map[string][]byte, error) {
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

// Helper to create a zip file
func buildCmdZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "cmd_pack.zip")
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
			t.Fatalf("failed to write data: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return outPath
}

func updateCmdManifest(entries map[string][]byte, decisionID, rootHash string) error {
	manifestFiles := make(map[string]verifier.PackFileMetadata)
	for name, data := range entries {
		if name == "manifest.json" {
			continue
		}
		h := sha256.Sum256(data)
		manifestFiles[name] = verifier.PackFileMetadata{
			SHA256: hex.EncodeToString(h[:]),
			Size:   int64(len(data)),
		}
	}
	manifest := verifier.EvidencePackManifest{
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

func loadCmdRSAPrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
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

func signCmdPayloadRSA(privKey *rsa.PrivateKey, payload map[string]any) (string, error) {
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
// CLI Adversarial Tests
// -------------------------------------------------------------

func TestCLI_Adversarial_ZipSlip(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readCmdZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	entries := copyCmdEntries(baseEntries)
	entries["../../evil.txt"] = []byte("MALICIOUS ZIP SLIP EXPLOIT VIA CLI")
	packPath := buildCmdZip(t, entries)

	var stdout, stderr bytes.Buffer
	code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
	if code != int(verifier.ExitGeneralFail) {
		t.Errorf("expected exit code %d (ExitGeneralFail), got %d", verifier.ExitGeneralFail, code)
	}
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "Zip slip detected") {
		t.Errorf("expected output to mention Zip slip detected, got: %s", combined)
	}
}

func TestCLI_Adversarial_SingleBitTampering(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readCmdZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	var baseManifest verifier.EvidencePackManifest
	json.Unmarshal(baseEntries["manifest.json"], &baseManifest)

	// 1. manifest.json syntax corruption -> exit 1
	t.Run("CLI_Tamper_ManifestJSON_Exit1", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		entries["manifest.json"][0] ^= 0x01
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitManifestFail) {
			t.Errorf("expected exit code 1, got %d", code)
		}
	})

	// 2. events.json bit flip -> exit 1
	t.Run("CLI_Tamper_EventsJSON_Exit1", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		entries["events.json"][20] ^= 0x01
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitManifestFail) {
			t.Errorf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Hash mismatch") {
			t.Errorf("expected Hash mismatch in output, got: %s", stdout.String())
		}
	})

	// 3. merkle_proof.json root altered + updated manifest -> exit 2
	t.Run("CLI_Tamper_MerkleProof_Exit2", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		var proof verifier.MerkleProofData
		json.Unmarshal(entries["merkle_proof.json"], &proof)
		proof.RootHash = "0000000000000000000000000000000000000000000000000000000000000000"
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes
		updateCmdManifest(entries, baseManifest.DecisionID, proof.RootHash)
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitMerkleFail) {
			t.Errorf("expected exit code 2, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Merkle root mismatch") {
			t.Errorf("expected Merkle root mismatch in output, got: %s", stdout.String())
		}
	})

	// 4. signature_1.json signature_hex bit altered + updated manifest -> exit 3
	t.Run("CLI_Tamper_Signature1_Exit3", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		var sig verifier.SignatureRecord
		json.Unmarshal(entries["signatures/signature_1.json"], &sig)
		sig.SignatureHex = "00" + sig.SignatureHex[2:]
		sigBytes, _ := canonical.Marshal(sig)
		entries["signatures/signature_1.json"] = sigBytes
		updateCmdManifest(entries, baseManifest.DecisionID, baseManifest.RootHash)
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitSignatureFail) {
			t.Errorf("expected exit code 3, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Signature verification failed") {
			t.Errorf("expected Signature verification failed in output, got: %s", stdout.String())
		}
	})

	// 5. signer_1.pem corrupted base64 + updated manifest -> exit 4
	t.Run("CLI_Tamper_SignerCert_Exit4", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		certStr := string(entries["certs/signer_1.pem"])
		lines := strings.Split(certStr, "\n")
		lines[1] = "A" + lines[1][1:]
		entries["certs/signer_1.pem"] = []byte(strings.Join(lines, "\n"))
		updateCmdManifest(entries, baseManifest.DecisionID, baseManifest.RootHash)
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitCertFail) {
			t.Errorf("expected exit code 4, got %d", code)
		}
	})
}

func TestCLI_Adversarial_PolicyBypass(t *testing.T) {
	validPackPath := filepath.Join(fixturesDir(t), "valid_pack.zip")
	baseEntries, err := readCmdZipEntries(validPackPath)
	if err != nil {
		t.Fatalf("failed to read valid pack: %v", err)
	}

	var baseManifest verifier.EvidencePackManifest
	json.Unmarshal(baseEntries["manifest.json"], &baseManifest)

	// Policy 1: Creator self-approval
	t.Run("CLI_CreatorSelfApproval_Exit5", func(t *testing.T) {
		entries := copyCmdEntries(baseEntries)
		var events []map[string]any
		json.Unmarshal(entries["events.json"], &events)
		events[0]["creator_id"] = "approver-user-01"
		eventsBytes, _ := canonical.Marshal(events)
		entries["events.json"] = eventsBytes

		firstEventCanon, _ := canonical.Marshal(events[0])
		h := sha256.Sum256(firstEventCanon)
		leafHash := hex.EncodeToString(h[:])
		hRoot := sha256.Sum256([]byte(leafHash + leafHash))
		rootHash := hex.EncodeToString(hRoot[:])

		var proof verifier.MerkleProofData
		json.Unmarshal(entries["merkle_proof.json"], &proof)
		proof.LeafHash = leafHash
		proof.RootHash = rootHash
		proof.AuditPath = []string{leafHash}
		proofBytes, _ := canonical.Marshal(proof)
		entries["merkle_proof.json"] = proofBytes

		updateCmdManifest(entries, baseManifest.DecisionID, rootHash)
		packPath := buildCmdZip(t, entries)

		var stdout, stderr bytes.Buffer
		code := ExecuteWithIO([]string{"verify", packPath}, &stdout, &stderr)
		if code != int(verifier.ExitPolicyFail) {
			t.Errorf("expected exit code 5, got %d", code)
		}
		if !strings.Contains(stdout.String(), "creator cannot approve own decision") {
			t.Errorf("expected creator self-approval error, got: %s", stdout.String())
		}
	})

	// Policy 2: Dwell time boundary 9s vs 10s with --min-dwell 10
	t.Run("CLI_DwellTime_Boundary_9s_vs_10s", func(t *testing.T) {
		certsDir, _ := filepath.Abs("../../../tests/fixtures/certs")
		key1Bytes, _ := os.ReadFile(filepath.Join(certsDir, "signer_1.key"))
		privKey1, err := loadCmdRSAPrivateKey(key1Bytes)
		if err != nil {
			t.Fatalf("failed to parse private key: %v", err)
		}

		craftDwellPack := func(dwellSec int) string {
			entries := copyCmdEntries(baseEntries)
			var sig1 verifier.SignatureRecord
			json.Unmarshal(entries["signatures/signature_1.json"], &sig1)
			sig1.SignedPayload["dwell_time_seconds"] = dwellSec
			newSigHex, _ := signCmdPayloadRSA(privKey1, sig1.SignedPayload)
			sig1.SignatureHex = newSigHex
			sig1Bytes, _ := canonical.Marshal(sig1)
			entries["signatures/signature_1.json"] = sig1Bytes
			updateCmdManifest(entries, baseManifest.DecisionID, baseManifest.RootHash)
			return buildCmdZip(t, entries)
		}

		// Dwell 9s with --min-dwell 10 -> MUST FAIL exit code 5
		pack9s := craftDwellPack(9)
		var out9, err9 bytes.Buffer
		code9 := ExecuteWithIO([]string{"verify", pack9s, "--min-dwell", "10"}, &out9, &err9)
		if code9 != int(verifier.ExitPolicyFail) {
			t.Errorf("expected exit code 5 for 9s dwell, got %d", code9)
		}
		if !strings.Contains(out9.String(), "Approver dwell time 9s < minimum 10s") {
			t.Errorf("expected dwell error message, got: %s", out9.String())
		}

		// Dwell 10s with --min-dwell 10 -> MUST PASS exit code 0
		pack10s := craftDwellPack(10)
		var out10, err10 bytes.Buffer
		code10 := ExecuteWithIO([]string{"verify", pack10s, "--min-dwell", "10"}, &out10, &err10)
		if code10 != int(verifier.ExitSuccess) {
			t.Errorf("expected exit code 0 for 10s dwell, got %d (err: %s)", code10, out10.String())
		}
		if strings.TrimSpace(out10.String()) != "VERIFICATION_SUCCESS" {
			t.Errorf("expected VERIFICATION_SUCCESS, got: %s", out10.String())
		}

		// Also test with shorthand -d 10 flag
		var out10Short, err10Short bytes.Buffer
		code10Short := ExecuteWithIO([]string{"verify", pack10s, "-d", "10"}, &out10Short, &err10Short)
		if code10Short != int(verifier.ExitSuccess) {
			t.Errorf("expected exit code 0 for 10s dwell with -d 10, got %d", code10Short)
		}
	})
}
