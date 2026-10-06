package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

func TestProxy_ShadowAI_MissingHeader_403(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), nil, rm, nil)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`))
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	var errResp registry.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error != "Missing X-AI-System-ID header: Shadow AI detected" {
		t.Fatalf("unexpected error response: %s", errResp.Error)
	}
}

func TestProxy_ShadowAI_Unregistered_403(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), nil, rm, nil)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`))
	req.Header.Set(registry.HeaderAISystemID, "rogue-agent-99")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	var errResp registry.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error != "Unregistered AI system 'rogue-agent-99': Shadow AI rejected" {
		t.Fatalf("unexpected error response: %s", errResp.Error)
	}
}

func TestProxy_InterceptMode_202(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	rm := registry.NewRegistryManagerWithDefaults()
	store := dualmode.NewMemoryDecisionStore()
	queue := ledger.NewBoundedQueue(100, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, store)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Vay 10 tỷ"}],"requires_approval":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "credit-advisor-v1")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status 202 Accepted, got %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/api/v1/decisions/dec-llm-") {
		t.Fatalf("unexpected Location header: %s", location)
	}

	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "PENDING_APPROVAL" {
		t.Fatalf("unexpected status: %s", resp["status"])
	}
	if !strings.HasPrefix(resp["decision_id"], "dec-llm-") {
		t.Fatalf("unexpected decision_id: %s", resp["decision_id"])
	}

	// Verify saved in decision store
	record, err := store.Get(resp["decision_id"])
	if err != nil || record.Status != dualmode.StatusPending {
		t.Fatalf("record not properly persisted in store: %v", record)
	}
}

func TestProxy_UpstreamUnreachable_502(t *testing.T) {
	// Point to unreachable local port
	u, _ := url.Parse("http://127.0.0.1:59999")
	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), nil, rm, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d", rec.Code)
	}
	var errResp OpenAIErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error.Code != 502 || !strings.Contains(errResp.Error.Message, "connection refused") {
		t.Fatalf("unexpected OpenAI error body: %+v", errResp)
	}
}

func TestProxy_Upstream503_PassThrough(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service temporarily overloaded"}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), nil, rm, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}
}

func TestProxy_HopByHopStripped(t *testing.T) {
	var forwardedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ChatCompletionResponse{
			ID:    "resp-1",
			Model: "gpt-4o",
			Choices: []NonStreamingChoice{
				{Message: ChatMessage{Role: "assistant", Content: "OK"}},
			},
		})
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), nil, rm, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("X-Custom-Client", "test-client")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if forwardedHeaders.Get("Upgrade") != "" {
		t.Fatalf("Upgrade header was not stripped")
	}
	if forwardedHeaders.Get("X-Custom-Client") != "test-client" {
		t.Fatalf("Custom client header was not preserved")
	}
}

func TestProxy_NonStreaming_WithPIIAndLedger(t *testing.T) {
	var receivedUpstreamBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUpstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ChatCompletionResponse{
			ID:    "resp-pii-1",
			Model: "gpt-4o",
			Choices: []NonStreamingChoice{
				{Message: ChatMessage{Role: "assistant", Content: "Đã ghi nhận thông tin."}},
			},
		})
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	rawPrompt := "Khách hàng CCCD 001090012345 cần vay 500tr"
	body := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":"%s"}]}`, rawPrompt)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	req.Header.Set("X-Correlation-ID", "corr-pii-test-01")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// Verify upstream received masked prompt
	if strings.Contains(string(receivedUpstreamBody), "001090012345") {
		t.Fatalf("raw CCCD leaked upstream: %s", string(receivedUpstreamBody))
	}
	if !strings.Contains(string(receivedUpstreamBody), "001******345") {
		t.Fatalf("masked CCCD not found in upstream body: %s", string(receivedUpstreamBody))
	}

	// Verify ledger queue received envelope
	select {
	case event := <-queue.Events():
		if event.CorrelationID != "corr-pii-test-01" {
			t.Fatalf("unexpected correlation ID: %s", event.CorrelationID)
		}
		if !event.PIIFlag || len(event.PIIDetected) != 1 || event.PIIDetected[0] != "CCCD" {
			t.Fatalf("unexpected PII detected: %v", event.PIIDetected)
		}
		if !strings.Contains(event.InputPayload, "001090012345") {
			t.Fatalf("expected raw CCCD in InputPayload: %s", event.InputPayload)
		}
		if !strings.Contains(event.InputMasked, "001******345") {
			t.Fatalf("expected masked CCCD in InputMasked: %s", event.InputMasked)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for audit event envelope in queue")
	}
}

func TestProxy_SSEStreaming_WithLedger(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Thẩm định \"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"thành công.\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hotline 0912345678"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	req.Header.Set("X-Correlation-ID", "corr-sse-test-02")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// Verify client received stream chunks
	streamOutput := rec.Body.String()
	if !strings.Contains(streamOutput, "Thẩm định ") || !strings.Contains(streamOutput, "data: [DONE]") {
		t.Fatalf("unexpected stream output: %s", streamOutput)
	}

	// Verify ledger queue received envelope with assembled output
	select {
	case event := <-queue.Events():
		if event.CorrelationID != "corr-sse-test-02" {
			t.Fatalf("unexpected correlation ID: %s", event.CorrelationID)
		}
		if !event.PIIFlag || len(event.PIIDetected) != 1 || event.PIIDetected[0] != "PHONE" {
			t.Fatalf("unexpected PII detected: %v", event.PIIDetected)
		}
		if !strings.Contains(event.OutputPayload, "Thẩm định thành công.") {
			t.Fatalf("unexpected OutputPayload: %s", event.OutputPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for audit event in queue")
	}
}

func BenchmarkProxy_50KBPayload_LatencyOverhead(b *testing.B) {
	// Construct 50KB payload
	largeText := strings.Repeat("Tài chính doanh nghiệp và kiểm toán rủi ro tín dụng. ", 1000)
	respPayload, _ := json.Marshal(ChatCompletionResponse{
		ID:    "bench-50k",
		Model: "gpt-4o",
		Choices: []NonStreamingChoice{
			{Message: ChatMessage{Role: "assistant", Content: "OK"}},
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respPayload)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(10000, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"model": "securities-quant-advisor-v1",
		"messages": []map[string]string{
			{"role": "user", "content": largeText},
		},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(bodyBytes)))
		req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}

func TestProxy_UpstreamTimeout_504(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow upstream exceeding proxy timeout
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	cfg := DefaultProxyConfig(u)
	cfg.UpstreamTimeout = 25 * time.Millisecond // Tight timeout to trigger DeadlineExceeded
	p := NewProxyHandler(cfg, nil, rm, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Timeout test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected status 504 Gateway Timeout, got %d", rec.Code)
	}

	var errResp OpenAIErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error.Code != 504 || errResp.Error.Type != "gateway_timeout_error" || !strings.Contains(errResp.Error.Message, "timeout") {
		t.Fatalf("unexpected OpenAI timeout error body: %+v", errResp)
	}
}

