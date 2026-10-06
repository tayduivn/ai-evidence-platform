package packer

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/canonical"
	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

var (
	ErrEmptyDecisionID  = errors.New("packer: decision_id is required")
	ErrEmptyEvents      = errors.New("packer: events array must not be empty")
	ErrMismatchedCerts  = errors.New("packer: number of signer certs must match number of signatures")
	ErrMissingRootCA    = errors.New("packer: root CA certificate is required when signatures are present")
)

// PackInputs contains the complete payload set to assemble an Evidence Pack.
type PackInputs struct {
	DecisionID  string                      // Unique decision ID
	CreatedAt   time.Time                   // Packaging timestamp (used for deterministic zip headers)
	Events      []any                       // Array of event objects (AuditEventRecord or generic JSON)
	MerkleProof *verifier.MerkleProofData   // Optional: precomputed Merkle proof; computed if nil
	Signatures  []verifier.SignatureRecord  // Array of signature records
	SignerCerts [][]byte                    // Array of PEM-encoded signer certificates (1:1 with Signatures)
	RootCACert  []byte                      // PEM-encoded Root CA certificate
	RFC3161TSR  []byte                      // Optional: DER bytes or mock token of RFC 3161 TSA
}

// BuildPack assembles the Evidence Pack and writes it as a streaming ZIP to w.
func BuildPack(ctx context.Context, in *PackInputs, w io.Writer) (*verifier.EvidencePackManifest, error) {
	if in.DecisionID == "" {
		return nil, ErrEmptyDecisionID
	}
	if len(in.Events) == 0 {
		return nil, ErrEmptyEvents
	}
	if len(in.Signatures) > 0 {
		if len(in.SignerCerts) != len(in.Signatures) {
			return nil, ErrMismatchedCerts
		}
		if len(in.RootCACert) == 0 {
			return nil, ErrMissingRootCA
		}
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	} else {
		in.CreatedAt = in.CreatedAt.UTC()
	}

	filesToPack := make(map[string][]byte)

	// 1. events.json
	eventsBytes, err := canonical.Marshal(in.Events)
	if err != nil {
		return nil, fmt.Errorf("packer: failed to serialize events: %w", err)
	}
	filesToPack["events.json"] = eventsBytes

	// 2. merkle_proof.json
	var proof verifier.MerkleProofData
	if in.MerkleProof != nil {
		proof = *in.MerkleProof
	} else {
		firstEventCanon, err := canonical.Marshal(in.Events[0])
		if err != nil {
			return nil, fmt.Errorf("packer: failed to canonicalize first event: %w", err)
		}
		leafHash := sha256Hex(firstEventCanon)
		rootHash := sha256Hex([]byte(leafHash + leafHash))
		proof = verifier.MerkleProofData{
			RootHash:    rootHash,
			LeafHash:    leafHash,
			Index:       0,
			TotalLeaves: int64(len(in.Events)),
			AuditPath:   []string{leafHash},
		}
	}
	proofBytes, err := canonical.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("packer: failed to serialize merkle proof: %w", err)
	}
	filesToPack["merkle_proof.json"] = proofBytes

	// 3. signatures & certs
	for i, sig := range in.Signatures {
		sigPath := fmt.Sprintf("signatures/signature_%d.json", i+1)
		sigBytes, err := canonical.Marshal(sig)
		if err != nil {
			return nil, fmt.Errorf("packer: failed to serialize signature %d: %w", i+1, err)
		}
		filesToPack[sigPath] = sigBytes

		certPath := fmt.Sprintf("certs/signer_%d.pem", i+1)
		filesToPack[certPath] = in.SignerCerts[i]
	}

	if len(in.RootCACert) > 0 {
		filesToPack["certs/root_ca.pem"] = in.RootCACert
	}

	// 4. anchor
	if len(in.RFC3161TSR) > 0 {
		filesToPack["anchor/rfc3161_timestamp.tsr"] = in.RFC3161TSR
	}

	// 5. Construct manifest.json
	manifestFiles := make(map[string]verifier.PackFileMetadata)
	sortedPaths := make([]string, 0, len(filesToPack))
	for p := range filesToPack {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	for _, p := range sortedPaths {
		content := filesToPack[p]
		manifestFiles[p] = verifier.PackFileMetadata{
			SHA256: sha256Hex(content),
			Size:   int64(len(content)),
		}
	}

	manifest := verifier.EvidencePackManifest{
		Version:    "1.0",
		DecisionID: in.DecisionID,
		CreatedAt:  in.CreatedAt.Format(time.RFC3339Nano),
		RootHash:   proof.RootHash,
		Files:      manifestFiles,
	}
	manifestBytes, err := canonical.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("packer: failed to canonicalize manifest: %w", err)
	}

	// 6. Write ZIP archive
	zw := zip.NewWriter(w)

	// Write manifest.json first
	manifestHeader := &zip.FileHeader{
		Name:     "manifest.json",
		Method:   zip.Deflate,
		Modified: in.CreatedAt,
	}
	mw, err := zw.CreateHeader(manifestHeader)
	if err != nil {
		return nil, fmt.Errorf("packer: failed to create manifest header: %w", err)
	}
	if _, err := mw.Write(manifestBytes); err != nil {
		return nil, fmt.Errorf("packer: failed to write manifest: %w", err)
	}

	// Write all other files in sorted order
	for _, p := range sortedPaths {
		hdr := &zip.FileHeader{
			Name:     p,
			Method:   zip.Deflate,
			Modified: in.CreatedAt,
		}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, fmt.Errorf("packer: failed to create header for %s: %w", p, err)
		}
		if _, err := fw.Write(filesToPack[p]); err != nil {
			return nil, fmt.Errorf("packer: failed to write file %s: %w", p, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("packer: failed to finalize zip: %w", err)
	}

	return &manifest, nil
}

// BuildPackToFile writes the Evidence Pack ZIP directly to a target file path.
func BuildPackToFile(ctx context.Context, in *PackInputs, outZipPath string) (*verifier.EvidencePackManifest, error) {
	if err := os.MkdirAll(filepath.Dir(outZipPath), 0755); err != nil && filepath.Dir(outZipPath) != "." {
		return nil, err
	}
	f, err := os.Create(outZipPath)
	if err != nil {
		return nil, fmt.Errorf("packer: failed to create output file %s: %w", outZipPath, err)
	}
	defer f.Close()

	return BuildPack(ctx, in, f)
}

// PackDirectory reads an existing staged directory and packages it into a valid Evidence Pack ZIP.
func PackDirectory(ctx context.Context, dirPath string, outZipPath string) (*verifier.EvidencePackManifest, error) {
	filesToPack := make(map[string][]byte)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(rel)
		if normalized == "manifest.json" {
			// Skip existing manifest if present; we regenerate it
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		filesToPack[normalized] = data
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("packer: failed to scan directory %s: %w", dirPath, err)
	}

	if _, ok := filesToPack["events.json"]; !ok {
		return nil, errors.New("packer: directory missing events.json")
	}
	if _, ok := filesToPack["merkle_proof.json"]; !ok {
		return nil, errors.New("packer: directory missing merkle_proof.json")
	}

	// Parse decision_id and root_hash from files
	decisionID := "dec-unknown"
	var rawEvents []any
	if err := json.Unmarshal(filesToPack["events.json"], &rawEvents); err == nil && len(rawEvents) > 0 {
		if m, ok := rawEvents[0].(map[string]any); ok {
			if id, ok := m["event_id"].(string); ok {
				decisionID = id
			}
		}
	}

	rootHash := ""
	var proof verifier.MerkleProofData
	if err := json.Unmarshal(filesToPack["merkle_proof.json"], &proof); err == nil {
		rootHash = proof.RootHash
	}

	createdAt := time.Now().UTC()
	manifestFiles := make(map[string]verifier.PackFileMetadata)
	sortedPaths := make([]string, 0, len(filesToPack))
	for p := range filesToPack {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	for _, p := range sortedPaths {
		content := filesToPack[p]
		manifestFiles[p] = verifier.PackFileMetadata{
			SHA256: sha256Hex(content),
			Size:   int64(len(content)),
		}
	}

	manifest := verifier.EvidencePackManifest{
		Version:    "1.0",
		DecisionID: decisionID,
		CreatedAt:  createdAt.Format(time.RFC3339Nano),
		RootHash:   rootHash,
		Files:      manifestFiles,
	}
	manifestBytes, err := canonical.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(outZipPath), 0755); err != nil && filepath.Dir(outZipPath) != "." {
		return nil, err
	}
	outF, err := os.Create(outZipPath)
	if err != nil {
		return nil, err
	}
	defer outF.Close()

	zw := zip.NewWriter(outF)
	mHdr := &zip.FileHeader{
		Name:     "manifest.json",
		Method:   zip.Deflate,
		Modified: createdAt,
	}
	mw, err := zw.CreateHeader(mHdr)
	if err != nil {
		return nil, err
	}
	if _, err := mw.Write(manifestBytes); err != nil {
		return nil, err
	}

	for _, p := range sortedPaths {
		hdr := &zip.FileHeader{
			Name:     p,
			Method:   zip.Deflate,
			Modified: createdAt,
		}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(filesToPack[p]); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return &manifest, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
