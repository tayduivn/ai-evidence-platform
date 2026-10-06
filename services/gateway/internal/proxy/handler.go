package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/pii"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// ServeHTTP implements the reverse proxy handler for chat completions.
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// 1. Evaluate AI Registry
	systemID := strings.TrimSpace(r.Header.Get(registry.HeaderAISystemID))
	artifactHash := strings.TrimSpace(r.Header.Get(registry.HeaderAIArtifactHash))
	promptHash := strings.TrimSpace(r.Header.Get(registry.HeaderAIPromptHash))

	status, errMsg, entry := p.registry.EvaluateRequest(systemID, artifactHash, promptHash)
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(registry.ErrorResponse{
			Error: errMsg,
		})
		return
	}

	// Correlation ID handling
	corrID := r.Header.Get("X-Correlation-ID")
	if corrID == "" {
		corrID = "tx-" + uuid.New().String()
	}
	w.Header().Set("X-Correlation-ID", corrID)

	// 2. Read and parse request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		p.writeOpenAIError(w, http.StatusBadRequest, "Invalid request body", "invalid_request_error")
		return
	}
	_ = r.Body.Close()

	var req ChatCompletionRequest
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			p.writeOpenAIError(w, http.StatusBadRequest, "Malformed JSON request body", "invalid_request_error")
			return
		}
	}

	// 3. Dual-mode evaluation
	reqRequiresApproval := req.RequiresApproval != nil && *req.RequiresApproval
	entryRequiresApproval := entry != nil && entry.RequiresApproval
	mode := dualmode.Evaluate(r.Header.Get(dualmode.HeaderRequireApproval), reqRequiresApproval, entryRequiresApproval)

	// Extract prompt texts for PII scanning
	rawPrompt, maskedPrompt, piiDetected, modifiedReq := p.sanitizePrompt(req)

	if mode == dualmode.ModeIntercept {
		// Intercept & Approve Mode: halt upstream, create decision record, return 202
		decisionID := "dec-llm-" + uuid.New().String()
		pollURL := "/api/v1/decisions/" + decisionID + "/status"

		if p.decisionStore != nil {
			_ = p.decisionStore.Save(&dualmode.DecisionRecord{
				DecisionID:    decisionID,
				CorrelationID: corrID,
				AISystemID:    systemID,
				SystemType:    "llm",
				ModelVersion:  req.Model,
				Status:        dualmode.StatusPending,
				RawInput:      rawPrompt,
				MaskedInput:   maskedPrompt,
				CreatedAt:     time.Now().UTC(),
				UpdatedAt:     time.Now().UTC(),
			})
		}

		// Enqueue interception audit event
		p.dispatchAuditEvent(&ledger.AuditEventEnvelope{
			EventID:          uuid.New().String(),
			CorrelationID:    corrID,
			Source:           ledger.SourceGatewayLLM,
			AISystemID:       systemID,
			SystemType:       "llm",
			ModelVersion:     req.Model,
			EventType:        ledger.EventTypeHumanApproval,
			InputPayload:     formatPayloadJSON("prompt", rawPrompt),
			InputMasked:      formatPayloadJSON("prompt", maskedPrompt),
			PIIDetected:      piiDetected,
			PIIFlag:          len(piiDetected) > 0,
			ClientIP:         r.RemoteAddr,
			UserAgent:        r.UserAgent(),
			LatencyMS:        time.Since(startTime).Milliseconds(),
			Status:           dualmode.StatusPendingApproval,
			Timestamp:        time.Now().UTC(),
		})

		w.Header().Set("Location", pollURL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":        "PENDING_APPROVAL",
			"decision_id":   decisionID,
			"correlation_id": corrID,
			"poll_url":      pollURL,
		})
		return
	}

	// 4. Audit-Only Mode: Forward to upstream LLM
	forwardedBytes, err := json.Marshal(modifiedReq)
	if err != nil {
		forwardedBytes = bodyBytes
	}

	targetURL := p.cfg.UpstreamURL.ResolveReference(&url.URL{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	})

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), bytes.NewReader(forwardedBytes))
	if err != nil {
		p.writeOpenAIError(w, http.StatusInternalServerError, "Failed to create upstream request", "gateway_internal_error")
		return
	}

	// Copy headers, stripping hop-by-hop
	for k, vv := range r.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}
	upstreamReq.Header.Set("X-Correlation-ID", corrID)
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(forwardedBytes)))

	// Execute upstream request
	upstreamResp, err := p.client.Do(upstreamReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || osIsTimeout(err) {
			p.writeOpenAIError(w, http.StatusGatewayTimeout, "Upstream LLM timeout", "gateway_timeout_error")
			return
		}
		p.writeOpenAIError(w, http.StatusBadGateway, "Upstream LLM unavailable: connection refused", "gateway_upstream_error")
		return
	}
	defer upstreamResp.Body.Close()

	// Upstream errors (>=400) pass-through directly
	if upstreamResp.StatusCode >= 400 {
		for k, vv := range upstreamResp.Header {
			if hopByHopHeaders[strings.ToLower(k)] {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	// 5. Streaming vs Non-Streaming Pass-Through
	if req.Stream {
		acc := NewSSEAccumulator()
		accResult, _ := p.StreamPassThrough(r.Context(), w, upstreamResp.Body, acc)

		// Non-blocking dispatch to ledger queue
		p.dispatchAuditEvent(&ledger.AuditEventEnvelope{
			EventID:          uuid.New().String(),
			CorrelationID:    corrID,
			Source:           ledger.SourceGatewayLLM,
			AISystemID:       systemID,
			SystemType:       "llm",
			ModelVersion:     accResult.Model,
			EventType:        ledger.EventTypeLLMInference,
			InputPayload:     formatPayloadJSON("prompt", rawPrompt),
			OutputPayload:    accResult.JSONOutputPayload,
			InputMasked:      formatPayloadJSON("prompt", maskedPrompt),
			OutputMasked:     accResult.JSONOutputPayload,
			PIIDetected:      piiDetected,
			PIIFlag:          len(piiDetected) > 0,
			ClientIP:         r.RemoteAddr,
			UserAgent:        r.UserAgent(),
			LatencyMS:        time.Since(startTime).Milliseconds(),
			TokensUsage:      accResult.TokensUsage,
			Status:           accResult.Status,
			Timestamp:        time.Now().UTC(),
		})
		return
	}

	// Non-Streaming response
	respBodyBytes, readErr := io.ReadAll(upstreamResp.Body)
	if readErr != nil {
		p.writeOpenAIError(w, http.StatusBadGateway, "Error reading upstream response", "gateway_upstream_error")
		return
	}

	for k, vv := range upstreamResp.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(respBodyBytes)

	// Parse non-streaming response for audit recording
	var chatResp ChatCompletionResponse
	var outputText string
	var usage *ledger.TokenUsage
	if jsonErr := json.Unmarshal(respBodyBytes, &chatResp); jsonErr == nil {
		if len(chatResp.Choices) > 0 {
			if strContent, ok := chatResp.Choices[0].Message.Content.(string); ok {
				outputText = strContent
			}
		}
		usage = chatResp.Usage
	}

	if usage == nil {
		tokens := estimateTokenCount(outputText)
		usage = &ledger.TokenUsage{
			CompletionTokens: tokens,
			TotalTokens:      tokens,
		}
	}

	p.dispatchAuditEvent(&ledger.AuditEventEnvelope{
		EventID:          uuid.New().String(),
		CorrelationID:    corrID,
		Source:           ledger.SourceGatewayLLM,
		AISystemID:       systemID,
		SystemType:       "llm",
		ModelVersion:     req.Model,
		EventType:        ledger.EventTypeLLMInference,
		InputPayload:     formatPayloadJSON("prompt", rawPrompt),
		OutputPayload:    formatPayloadJSON("response", outputText),
		InputMasked:      formatPayloadJSON("prompt", maskedPrompt),
		OutputMasked:     formatPayloadJSON("response", outputText),
		PIIDetected:      piiDetected,
		PIIFlag:          len(piiDetected) > 0,
		ClientIP:         r.RemoteAddr,
		UserAgent:        r.UserAgent(),
		LatencyMS:        time.Since(startTime).Milliseconds(),
		TokensUsage:      usage,
		Status:           "COMPLETED",
		Timestamp:        time.Now().UTC(),
	})
}

// sanitizePrompt extracts the prompt string, detects and masks PII, and returns modified request.
func (p *ProxyHandler) sanitizePrompt(req ChatCompletionRequest) (string, string, []string, ChatCompletionRequest) {
	var rawPrompts []string
	var maskedPrompts []string
	detectedSet := make(map[string]bool)

	modified := req
	newMessages := make([]ChatMessage, len(req.Messages))

	for i, m := range req.Messages {
		newMessages[i] = m
		if contentStr, ok := m.Content.(string); ok {
			rawPrompts = append(rawPrompts, contentStr)
			masked, detected := pii.ScanAndMask(contentStr)
			maskedPrompts = append(maskedPrompts, masked)
			newMessages[i].Content = masked
			for _, d := range detected {
				detectedSet[d] = true
			}
		}
	}
	modified.Messages = newMessages

	raw := strings.Join(rawPrompts, "\n")
	masked := strings.Join(maskedPrompts, "\n")

	var detectedList []string
	for k := range detectedSet {
		detectedList = append(detectedList, k)
	}

	return raw, masked, detectedList, modified
}

func (p *ProxyHandler) dispatchAuditEvent(envelope *ledger.AuditEventEnvelope) {
	if p.queue == nil || envelope == nil {
		return
	}
	go func() {
		_ = p.queue.Enqueue(envelope)
	}()
}

func (p *ProxyHandler) writeOpenAIError(w http.ResponseWriter, code int, msg, errType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(OpenAIErrorResponse{
		Error: OpenAIErrorBody{
			Message: msg,
			Type:    errType,
			Code:    code,
		},
	})
}

func osIsTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func formatPayloadJSON(key, val string) string {
	b, _ := json.Marshal(map[string]string{key: val})
	return string(b)
}
