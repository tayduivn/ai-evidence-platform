package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	tmpDir := t.TempDir()
	binName := "ai-evidence-cli"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tmpDir, binName)

	cmd := exec.Command("go", "build", "-trimpath", "-o", binPath, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v, output: %s", err, string(out))
	}
	return binPath
}

func fixturesDir(t *testing.T) string {
	abs, err := filepath.Abs("../../tests/fixtures/evidence_packs")
	if err != nil {
		t.Fatalf("failed to resolve fixtures directory: %v", err)
	}
	return abs
}

func TestSubprocess_AllSevenPacks(t *testing.T) {
	binPath := buildBinary(t)
	fDir := fixturesDir(t)

	tests := []struct {
		name         string
		packName     string
		flags        []string
		expectedCode int
		expectedMsg  string
	}{
		{
			name:         "Valid Pack",
			packName:     "valid_pack.zip",
			expectedCode: 0,
			expectedMsg:  "VERIFICATION_SUCCESS",
		},
		{
			name:         "Tampered Manifest",
			packName:     "tampered_manifest.zip",
			expectedCode: 1,
			expectedMsg:  "Hash mismatch",
		},
		{
			name:         "Tampered Merkle",
			packName:     "tampered_merkle.zip",
			expectedCode: 2,
			expectedMsg:  "Merkle root mismatch",
		},
		{
			name:         "Invalid Signature",
			packName:     "invalid_signature.zip",
			expectedCode: 3,
			expectedMsg:  "Signature verification failed",
		},
		{
			name:         "Untrusted Certificate",
			packName:     "untrusted_cert.zip",
			expectedCode: 4,
			expectedMsg:  "untrusted or not signed by Root CA",
		},
		{
			name:         "Policy Violation Duplicate Approver",
			packName:     "policy_violation_pack.zip",
			expectedCode: 5,
			expectedMsg:  "duplicate approver",
		},
		{
			name:         "Policy Violation High Min Dwell",
			packName:     "valid_pack.zip",
			flags:        []string{"--min-dwell", "100"},
			expectedCode: 5,
			expectedMsg:  "dwell time 15s < minimum 100s",
		},
		{
			name:         "Corrupt Archive",
			packName:     "corrupt_archive.zip",
			expectedCode: 6,
			expectedMsg:  "Corrupt or invalid zip archive",
		},
		{
			name:         "Non Existent File",
			packName:     "non_existent_pack_9999.zip",
			expectedCode: 6,
			expectedMsg:  "not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packFile := filepath.Join(fDir, tc.packName)
			args := []string{"verify", packFile}
			if len(tc.flags) > 0 {
				args = append(args, tc.flags...)
			}

			cmd := exec.Command(binPath, args...)
			out, err := cmd.CombinedOutput()
			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("command failed with non-exit error: %v", err)
				}
			}

			if exitCode != tc.expectedCode {
				t.Errorf("expected exit code %d, got %d (output: %s)", tc.expectedCode, exitCode, string(out))
			}
			if !strings.Contains(string(out), tc.expectedMsg) {
				t.Errorf("expected output to contain %q, got: %s", tc.expectedMsg, string(out))
			}
		})
	}
}

func TestSubprocess_InspectAndPack(t *testing.T) {
	binPath := buildBinary(t)
	fDir := fixturesDir(t)
	validPack := filepath.Join(fDir, "valid_pack.zip")

	// 1. inspect command
	inspectCmd := exec.Command(binPath, "inspect", validPack)
	out, err := inspectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect command failed: %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "EVIDENCE PACK INSPECTION") {
		t.Errorf("expected inspection header, got: %s", string(out))
	}

	// 2. inspect --json command
	inspectJSONCmd := exec.Command(binPath, "inspect", validPack, "--json")
	outJSON, err := inspectJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}
	if !strings.Contains(string(outJSON), `"pack_version"`) {
		t.Errorf("expected JSON output, got: %s", string(outJSON))
	}

	// 3. version command
	verCmd := exec.Command(binPath, "version")
	outVer, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.Contains(string(outVer), "ai-evidence-cli v1.0.0") {
		t.Errorf("expected version output, got: %s", string(outVer))
	}
}
