package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/proxy"
	"ei-evidence-platform/services/gateway/internal/registry"
)

func TestServer_HealthAndReady(t *testing.T) {
	router := NewRouter(RouterOptions{})

	// 1. Health
	reqHealth := httptest.NewRequest("GET", "/health", nil)
	recHealth := httptest.NewRecorder()
	router.ServeHTTP(recHealth, reqHealth)

	if recHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /health, got %d", recHealth.Code)
	}
	var healthResp HealthResponse
	_ = json.Unmarshal(recHealth.Body.Bytes(), &healthResp)
	if healthResp.Status != "UP" {
		t.Fatalf("expected status UP, got %s", healthResp.Status)
	}

	// 2. Ready
	reqReady := httptest.NewRequest("GET", "/ready", nil)
	recReady := httptest.NewRecorder()
	router.ServeHTTP(recReady, reqReady)

	if recReady.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /ready, got %d", recReady.Code)
	}
	var readyResp HealthResponse
	_ = json.Unmarshal(recReady.Body.Bytes(), &readyResp)
	if readyResp.Status != "READY" {
		t.Fatalf("expected status READY, got %s", readyResp.Status)
	}
}

func TestServer_MiddlewarePanicRecovery(t *testing.T) {
	h := Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated critical crash")
	}))

	req := httptest.NewRequest("GET", "/crash", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on panic, got %d", rec.Code)
	}
}

func TestServer_CorrelationIDInjection(t *testing.T) {
	var capturedID string
	h := CorrelationID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Context().Value(CorrelationIDContextKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: Custom header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Correlation-ID", "custom-tx-12345")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if capturedID != "custom-tx-12345" {
		t.Fatalf("expected custom correlation ID, got %s", capturedID)
	}
	if rec.Header().Get("X-Correlation-ID") != "custom-tx-12345" {
		t.Fatalf("expected response header X-Correlation-ID")
	}

	// Case 2: Generated
	req2 := httptest.NewRequest("GET", "/test", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if capturedID == "" {
		t.Fatalf("expected generated correlation ID")
	}
}

func TestServer_Lifecycle(t *testing.T) {
	store := dualmode.NewMemoryDecisionStore()
	router := NewRouter(RouterOptions{DecisionStore: store})
	srv := NewServer(0, router) // ephemeral port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		t.Fatalf("unexpected shutdown error: %v", err)
	}
}

func TestServer_Router_SSEStreaming_FlusherSuccess(t *testing.T) {
	// 1. Mock upstream LLM server streaming SSE chunks
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unsupported", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Chunk through router\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer ts.Close()

	// 2. Setup ProxyHandler and Router
	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	p := proxy.NewProxyHandler(proxy.DefaultProxyConfig(u), nil, rm, nil)
	router := NewRouter(RouterOptions{ProxyHandler: p})

	// 3. Issue SSE streaming request to /v1/chat/completions through the router (with AccessLogger middleware)
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Stream test"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-AI-System-ID", "securities-quant-advisor-v1")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// 4. Verify HTTP 200 and successful stream chunks
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK through router, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected text/event-stream content type, got %s", rec.Header().Get("Content-Type"))
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "Chunk through router") || !strings.Contains(bodyStr, "[DONE]") {
		t.Fatalf("expected streamed SSE chunks in response body, got %s", bodyStr)
	}
}
