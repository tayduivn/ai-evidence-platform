package inspector

import (
	"archive/zip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"ei-evidence-platform/cli/ai-evidence-cli/internal/verifier"
)

// InspectOptions configures the inspection engine.
type InspectOptions struct {
	ShowPayloads bool
}

// ApproverSummary details an individual approval in the audit trail.
type ApproverSummary struct {
	Index            int       `json:"index"`
	ApproverID       string    `json:"approver_id"`
	DwellTimeSeconds int       `json:"dwell_time_seconds"`
	SignerType       string    `json:"signer_type"`
	Algorithm        string    `json:"algorithm"`
	SignedAt         string    `json:"signed_at"`
	CertSubject      string    `json:"cert_subject,omitempty"`
	CertIssuer       string    `json:"cert_issuer,omitempty"`
	CertNotAfter     time.Time `json:"cert_not_after,omitempty"`
}

// TokenUsageSummary summarizes token metrics.
type TokenUsageSummary struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// InspectionReport contains comprehensive extracted forensic evidence.
type InspectionReport struct {
	PackVersion     string              `json:"pack_version"`
	DecisionID      string              `json:"decision_id"`
	CreatedAt       string              `json:"created_at"`
	Status          string              `json:"status"`
	AISystemID      string              `json:"ai_system_id,omitempty"`
	SystemType      string              `json:"system_type,omitempty"`
	ModelVersion    string              `json:"model_version,omitempty"`
	LatencyMS       int64               `json:"latency_ms,omitempty"`
	Tokens          *TokenUsageSummary  `json:"tokens,omitempty"`
	PIIDetected     []string            `json:"pii_detected,omitempty"`
	PromptMasked    string              `json:"prompt_masked,omitempty"`
	PromptRaw       string              `json:"prompt_raw,omitempty"`
	ResponseMasked  string              `json:"response_masked,omitempty"`
	ResponseRaw     string              `json:"response_raw,omitempty"`
	Approvers       []ApproverSummary   `json:"approvers"`
	MerkleRoot      string              `json:"merkle_root"`
	LeafHash        string              `json:"leaf_hash"`
	TSAAnchorStatus string              `json:"tsa_anchor_status"`
	TotalFiles      int                 `json:"total_files"`
	TotalBytes      int64               `json:"total_bytes"`
	Files           []string            `json:"files"`
}

// Inspect extracts and structures the forensic contents of an evidence pack ZIP.
func Inspect(packPath string, opts InspectOptions) (*InspectionReport, error) {
	st, err := os.Stat(packPath)
	if err != nil {
		return nil, fmt.Errorf("evidence pack not found: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", packPath)
	}

	zr, err := zip.OpenReader(packPath)
	if err != nil {
		return nil, fmt.Errorf("corrupt or invalid zip archive: %w", err)
	}
	defer zr.Close()

	fileMap := make(map[string]*zip.File)
	var totalBytes int64
	var fileList []string
	for _, f := range zr.File {
		fileMap[f.Name] = f
		fileList = append(fileList, f.Name)
		totalBytes += int64(f.UncompressedSize64)
	}
	sort.Strings(fileList)

	report := &InspectionReport{
		TotalFiles: len(zr.File),
		TotalBytes: totalBytes,
		Files:      fileList,
		Approvers:  make([]ApproverSummary, 0),
	}

	// 1. Read manifest.json
	if mf, ok := fileMap["manifest.json"]; ok {
		mBytes, err := readZip(mf)
		if err == nil {
			var m verifier.EvidencePackManifest
			if json.Unmarshal(mBytes, &m) == nil {
				report.PackVersion = m.Version
				report.DecisionID = m.DecisionID
				report.CreatedAt = m.CreatedAt
				report.MerkleRoot = m.RootHash
			}
		}
	}

	// 2. Read events.json
	if ef, ok := fileMap["events.json"]; ok {
		eBytes, err := readZip(ef)
		if err == nil {
			var rawEvents []map[string]any
			if json.Unmarshal(eBytes, &rawEvents) == nil && len(rawEvents) > 0 {
				ev := rawEvents[0]
				if report.DecisionID == "" {
					if id, ok := ev["event_id"].(string); ok {
						report.DecisionID = id
					}
				}
				if st, ok := ev["status"].(string); ok {
					report.Status = st
				}
				if sysID, ok := ev["ai_system_id"].(string); ok {
					report.AISystemID = sysID
				}
				if sysType, ok := ev["system_type"].(string); ok {
					report.SystemType = sysType
				}
				if mv, ok := ev["model_version"].(string); ok {
					report.ModelVersion = mv
				}
				if lat, ok := ev["latency_ms"].(float64); ok {
					report.LatencyMS = int64(lat)
				}
				if pii, ok := ev["pii_detected"].([]any); ok {
					for _, p := range pii {
						if str, ok := p.(string); ok {
							report.PIIDetected = append(report.PIIDetected, str)
						}
					}
				}
				if tu, ok := ev["tokens_usage"].(map[string]any); ok {
					report.Tokens = &TokenUsageSummary{
						PromptTokens:     getInt(tu["prompt_tokens"]),
						CompletionTokens: getInt(tu["completion_tokens"]),
						TotalTokens:      getInt(tu["total_tokens"]),
					}
				}

				// Payload extraction
				report.PromptMasked = extractText(ev["input_masked"])
				report.PromptRaw = extractText(ev["input_payload"])
				report.ResponseMasked = extractText(ev["output_masked"])
				report.ResponseRaw = extractText(ev["output_payload"])
			}
		}
	}

	// 3. Read merkle_proof.json
	if mp, ok := fileMap["merkle_proof.json"]; ok {
		mpBytes, err := readZip(mp)
		if err == nil {
			var proof verifier.MerkleProofData
			if json.Unmarshal(mpBytes, &proof) == nil {
				if report.MerkleRoot == "" {
					report.MerkleRoot = proof.RootHash
				}
				report.LeafHash = proof.LeafHash
			}
		}
	}

	// 4. Signatures & Certs
	var sigFiles []string
	for name := range fileMap {
		if strings.HasPrefix(name, "signatures/signature_") && strings.HasSuffix(name, ".json") {
			sigFiles = append(sigFiles, name)
		}
	}
	sort.Strings(sigFiles)

	for i, sigFile := range sigFiles {
		sBytes, err := readZip(fileMap[sigFile])
		if err != nil {
			continue
		}
		var sigRecord verifier.SignatureRecord
		if json.Unmarshal(sBytes, &sigRecord) != nil {
			continue
		}

		idx := strings.TrimPrefix(sigFile, "signatures/signature_")
		idx = strings.TrimSuffix(idx, ".json")
		certFile := fmt.Sprintf("certs/signer_%s.pem", idx)

		var subject, issuer string
		var notAfter time.Time
		if cf, ok := fileMap[certFile]; ok {
			cBytes, err := readZip(cf)
			if err == nil {
				block, _ := pem.Decode(cBytes)
				if block != nil {
					cert, err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						subject = cert.Subject.CommonName
						issuer = cert.Issuer.CommonName
						notAfter = cert.NotAfter
					}
				}
			}
		}

		signedAt := ""
		dwell := 0
		if sigRecord.SignedPayload != nil {
			if ts, ok := sigRecord.SignedPayload["timestamp"].(string); ok {
				signedAt = ts
			}
			dwell = getInt(sigRecord.SignedPayload["dwell_time_seconds"])
		}

		report.Approvers = append(report.Approvers, ApproverSummary{
			Index:            i + 1,
			ApproverID:       sigRecord.ApproverID,
			DwellTimeSeconds: dwell,
			SignerType:       sigRecord.SignerType,
			Algorithm:        sigRecord.Algorithm,
			SignedAt:         signedAt,
			CertSubject:      subject,
			CertIssuer:       issuer,
			CertNotAfter:     notAfter,
		})
	}

	// 5. TSA Anchor Status
	if tf, ok := fileMap["anchor/rfc3161_timestamp.tsr"]; ok {
		tBytes, err := readZip(tf)
		if err == nil {
			if strings.HasPrefix(string(tBytes), "MOCK_") {
				report.TSAAnchorStatus = "Present (Mock Token: anchor/rfc3161_timestamp.tsr)"
			} else {
				report.TSAAnchorStatus = fmt.Sprintf("Present (DER Token, %d bytes)", len(tBytes))
			}
		} else {
			report.TSAAnchorStatus = "Present (Unreadable)"
		}
	} else {
		report.TSAAnchorStatus = "Not Present"
	}

	return report, nil
}

// TextSummary formats the report into human-readable plain text.
func (r *InspectionReport) TextSummary(showPayloads bool) string {
	var b strings.Builder
	b.WriteString("================================================================================\n")
	b.WriteString(fmt.Sprintf("EVIDENCE PACK INSPECTION: %s\n", r.DecisionID))
	b.WriteString("================================================================================\n")
	b.WriteString(fmt.Sprintf("Pack Version    : %s\n", defaultStr(r.PackVersion, "1.0")))
	b.WriteString(fmt.Sprintf("Created At      : %s\n", r.CreatedAt))
	b.WriteString(fmt.Sprintf("Status          : %s\n", defaultStr(r.Status, "UNKNOWN")))

	sysDesc := r.AISystemID
	if r.SystemType != "" {
		sysDesc = fmt.Sprintf("%s (%s)", r.AISystemID, strings.ToUpper(r.SystemType))
	}
	if sysDesc != "" {
		b.WriteString(fmt.Sprintf("AI System ID    : %s\n", sysDesc))
	}
	if r.ModelVersion != "" {
		b.WriteString(fmt.Sprintf("Model Version   : %s\n", r.ModelVersion))
	}
	if r.LatencyMS > 0 {
		b.WriteString(fmt.Sprintf("Latency         : %d ms\n", r.LatencyMS))
	}
	if r.Tokens != nil {
		b.WriteString(fmt.Sprintf("Tokens          : Prompt: %d | Completion: %d | Total: %d\n",
			r.Tokens.PromptTokens, r.Tokens.CompletionTokens, r.Tokens.TotalTokens))
	}
	if len(r.PIIDetected) > 0 {
		b.WriteString(fmt.Sprintf("PII Detected    : [%s]\n", strings.Join(r.PIIDetected, ", ")))
	}

	b.WriteString("\n--- DECISION CONTENT ---\n")
	promptToShow := r.PromptMasked
	if showPayloads && r.PromptRaw != "" {
		promptToShow = r.PromptRaw
	}
	respToShow := r.ResponseMasked
	if showPayloads && r.ResponseRaw != "" {
		respToShow = r.ResponseRaw
	}
	if promptToShow != "" {
		b.WriteString(fmt.Sprintf("Prompt          : %s\n", promptToShow))
	}
	if respToShow != "" {
		b.WriteString(fmt.Sprintf("Response        : %s\n", respToShow))
	}

	if len(r.Approvers) > 0 {
		b.WriteString("\n--- APPROVAL TRAIL (4-Eyes Principle) ---\n")
		for _, app := range r.Approvers {
			b.WriteString(fmt.Sprintf("Approver %d      : %s\n", app.Index, app.ApproverID))
			b.WriteString(fmt.Sprintf("  Dwell Time    : %ds\n", app.DwellTimeSeconds))
			b.WriteString(fmt.Sprintf("  Signer Type   : %s\n", app.SignerType))
			b.WriteString(fmt.Sprintf("  Algorithm     : %s\n", app.Algorithm))
			if app.SignedAt != "" {
				b.WriteString(fmt.Sprintf("  Signed At     : %s\n", app.SignedAt))
			}
			if app.CertSubject != "" {
				b.WriteString(fmt.Sprintf("  Cert Subject  : %s\n", app.CertSubject))
			}
		}
	}

	b.WriteString("\n--- CRYPTOGRAPHIC INTEGRITY ---\n")
	b.WriteString(fmt.Sprintf("Merkle Root     : %s\n", r.MerkleRoot))
	if r.LeafHash != "" {
		b.WriteString(fmt.Sprintf("Leaf Hash       : %s\n", r.LeafHash))
	}
	b.WriteString(fmt.Sprintf("TSA Anchor      : %s\n", r.TSAAnchorStatus))
	b.WriteString(fmt.Sprintf("Enclosed Files  : %d files (total: %d bytes)\n", r.TotalFiles, r.TotalBytes))
	b.WriteString("================================================================================\n")

	return b.String()
}

func readZip(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func getInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case json.Number:
		n, _ := val.Int64()
		return int(n)
	default:
		return 0
	}
}

func extractText(v any) string {
	if v == nil {
		return ""
	}
	str, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	// If it's a JSON string with {"prompt":"..."}, parse inner text
	var inner map[string]any
	if json.Unmarshal([]byte(str), &inner) == nil {
		if p, ok := inner["prompt"].(string); ok {
			return p
		}
		if r, ok := inner["response"].(string); ok {
			return r
		}
	}
	return str
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
