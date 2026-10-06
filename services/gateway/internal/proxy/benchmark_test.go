package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

// BenchmarkProxyHandler_50KB_Overhead benchmarks the Go reverse proxy handler with a 50KB payload.
func BenchmarkProxyHandler_50KB_Overhead(b *testing.B) {
	// Upstream mock server returning instantaneous 200 OK JSON response
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-bench","object":"chat.completion","created":1700000000,"choices":[{"index":0,"message":{"role":"assistant","content":"Xác nhận kết quả phân tích hồ sơ tín dụng hợp lệ."},"finish_reason":"stop"}],"usage":{"prompt_tokens":120,"completion_tokens":25,"total_tokens":145}}`))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		b.Fatalf("failed to parse upstream url: %v", err)
	}

	queue := ledger.NewBoundedQueue(100000, nil)
	defer queue.Close()

	rm := registry.NewRegistryManagerWithDefaults()
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	// Load 50KB payload fixture
	fixturePath := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "payloads", "payload_50kb.json")
	payloadBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		// Fallback synthetic 50KB payload if fixture path differs
		payloadBytes = []byte(fmt.Sprintf(`{"model":"securities-quant-advisor-v1","messages":[{"role":"user","content":"%s"}]}`, strings.Repeat("A", 50*1024)))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(payloadBytes)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
		req.Header.Set("X-Correlation-ID", fmt.Sprintf("bench-%d", i))

		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected response code: %d", rec.Code)
		}
	}
}
