package verifier

import (
	"time"
)

// ExitCode defines the standardized verification exit codes (0 to 6).
type ExitCode int

const (
	ExitSuccess       ExitCode = 0 // Verification passed, emits VERIFICATION_SUCCESS
	ExitManifestFail  ExitCode = 1 // Manifest integrity failure (file missing, tampered, hash mismatch)
	ExitMerkleFail    ExitCode = 2 // Merkle proof failure (leaf or root mismatch)
	ExitSignatureFail ExitCode = 3 // Digital signature failure (missing signature, invalid bytes)
	ExitCertFail      ExitCode = 4 // Certificate chain failure (missing root/signer, expired, untrusted)
	ExitPolicyFail    ExitCode = 5 // Policy violation (dwell time < min, duplicate approver, creator self-approval)
	ExitGeneralFail   ExitCode = 6 // General unrecoverable error (file not found, corrupt zip, fatal I/O)
)

// VerifyOptions encapsulates configuration for the verification engine.
type VerifyOptions struct {
	MinDwellSeconds int
	RootCAOverride  []byte
	Verbose         bool
	VerifyTime      *time.Time
}

// EvidencePackManifest models manifest.json within the evidence pack.
type EvidencePackManifest struct {
	Version    string                      `json:"version"`
	DecisionID string                      `json:"decision_id"`
	CreatedAt  string                      `json:"created_at"`
	RootHash   string                      `json:"root_hash"`
	Files      map[string]PackFileMetadata `json:"files"`
}

// PackFileMetadata models per-file integrity metadata in manifest.json.
type PackFileMetadata struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// MerkleProofData models merkle_proof.json within the evidence pack.
type MerkleProofData struct {
	RootHash    string   `json:"root_hash"`
	LeafHash    string   `json:"leaf_hash"`
	Index       int64    `json:"index"`
	TotalLeaves int64    `json:"total_leaves"`
	AuditPath   []string `json:"audit_path"`
}

// SignatureRecord models signatures/signature_<idx>.json within the evidence pack.
type SignatureRecord struct {
	SignerType    string         `json:"signer_type"`
	ApproverID    string         `json:"approver_id"`
	SignedPayload map[string]any `json:"signed_payload"`
	SignatureHex  string         `json:"signature_hex"`
	Algorithm     string         `json:"algorithm"`
}

// CheckDetail describes individual verification layer status.
type CheckDetail struct {
	Passed  bool   `json:"passed"`
	Error   string `json:"error,omitempty"`
	Details any    `json:"details,omitempty"`
}

// VerificationReport contains complete results and structured diagnostics.
type VerificationReport struct {
	Status      string                 `json:"status"` // "SUCCESS" or "FAILED"
	ExitCode    ExitCode               `json:"exit_code"`
	Message     string                 `json:"message,omitempty"`
	Error       string                 `json:"error,omitempty"`
	DecisionID  string                 `json:"decision_id,omitempty"`
	VerifiedAt  time.Time              `json:"verified_at"`
	Checks      map[string]CheckDetail `json:"checks"`
	VerboseLogs []string               `json:"verbose_logs,omitempty"`
}
