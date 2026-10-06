package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

// 1. Adversarial SSE Stream Ingestion: UTF-8 and JSON Boundary Splits

func TestAdversarial_UTF8SplitAcrossChunks(t *testing.T) {
	acc := NewSSEAccumulator()

	// Vietnamese text: "Hồ Chí Minh: Tiền tệ & Tín dụng"
	// "Hồ" -> H (0x48), ồ (0xC3 0xB4)
	// "tiền" -> t, i, ề (0xE1 0xBB 0x81), n
	fullChunk := "data: {\"choices\":[{\"delta\":{\"content\":\"Hồ Chí Minh: Tiền tệ\"}}]}\n\n"
	fullBytes := []byte(fullChunk)

	// Split fullBytes into 3-byte chunks to intentionally slice multi-byte UTF-8 sequences
	chunkSize := 3
	for i := 0; i < len(fullBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(fullBytes) {
			end = len(fullBytes)
		}
		acc.ProcessBytes(fullBytes[i:end])
	}
	acc.ProcessBytes([]byte("data: [DONE]\n\n"))

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Hồ Chí Minh: Tiền tệ" {
		t.Fatalf("expected 'Hồ Chí Minh: Tiền tệ', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
}

func TestAdversarial_SingleByteFeeding(t *testing.T) {
	acc := NewSSEAccumulator()
	streamText := "data: {\"choices\":[{\"delta\":{\"content\":\"Adversarial 1-byte stream\"}}]}\n\ndata: [DONE]\n\n"

	// Feed one single byte at a time
	for i := 0; i < len(streamText); i++ {
		acc.ProcessBytes([]byte{streamText[i]})
	}

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Adversarial 1-byte stream" {
		t.Fatalf("expected 'Adversarial 1-byte stream', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
}

func TestAdversarial_JSONKeySplits(t *testing.T) {
	acc := NewSSEAccumulator()

	// Slicing right in the middle of keys: "cho" | "ices", "del" | "ta", "con" | "tent"
	c1 := "data: {\"cho"
	c2 := "ices\":[{\"del"
	c3 := "ta\":{\"con"
	c4 := "tent\":\"Split across keys\"}}]}\n\n"
	c5 := "data: [DONE]\n\n"

	acc.ProcessBytes([]byte(c1))
	acc.ProcessBytes([]byte(c2))
	acc.ProcessBytes([]byte(c3))
	acc.ProcessBytes([]byte(c4))
	acc.ProcessBytes([]byte(c5))

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Split across keys" {
		t.Fatalf("expected 'Split across keys', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
}

// 2. Burst arrivals with zero delay (chunk_delay_ms=0)

func TestAdversarial_BurstZeroDelay(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	totalChunks := 200
	var payload strings.Builder
	for i := 0; i < totalChunks; i++ {
		payload.WriteString(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"%d-\"}}]}\n\n", i))
	}
	payload.WriteString("data: [DONE]\n\n")

	body := io.NopCloser(strings.NewReader(payload.String()))
	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	start := time.Now()
	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("burst stream failed: %v", err)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
	// Verify all 200 tokens present and in order
	expectedStart := "0-1-2-"
	if !strings.HasPrefix(res.AssembledText, expectedStart) {
		t.Fatalf("expected assembled text to start with '%s', got '%s'", expectedStart, res.AssembledText[:20])
	}
	expectedEnd := "199-"
	if !strings.HasSuffix(res.AssembledText, expectedEnd) {
		t.Fatalf("expected assembled text to end with '%s', got '%s'", expectedEnd, res.AssembledText[len(res.AssembledText)-10:])
	}
	t.Logf("Processed %d burst chunks in %v", totalChunks, duration)
}

// 3. Empty stream, single token, and 10,000-token stream

func TestAdversarial_EmptyStream_OnlyDone(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	body := io.NopCloser(strings.NewReader("data: [DONE]\n\n"))
	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.AssembledText != "" {
		t.Fatalf("expected empty assembled text, got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
	if res.TokensUsage.CompletionTokens != 0 {
		t.Fatalf("expected 0 tokens, got %d", res.TokensUsage.CompletionTokens)
	}
}

func TestAdversarial_EmptyStream_ZeroBytes(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	body := io.NopCloser(strings.NewReader(""))
	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.AssembledText != "" {
		t.Fatalf("expected empty text, got '%s'", res.AssembledText)
	}
	if res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = false for 0-byte stream")
	}
}

func TestAdversarial_SingleToken_OK(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	body := io.NopCloser(strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n"))
	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.AssembledText != "OK" {
		t.Fatalf("expected 'OK', got '%s'", res.AssembledText)
	}
	if res.TokensUsage.CompletionTokens != 1 {
		t.Fatalf("expected 1 token, got %d", res.TokensUsage.CompletionTokens)
	}
}

func TestAdversarial_Large10000TokenStream(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	tokenCount := 10000
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		for i := 0; i < tokenCount; i++ {
			chunk := fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"tok \"}}]}\n\n")
			if _, err := pw.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_, _ = pw.Write([]byte("data: [DONE]\n\n"))
	}()

	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	start := time.Now()
	res, err := p.StreamPassThrough(context.Background(), rec, pr, acc)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("large stream failed: %v", err)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
	if res.TokensUsage == nil || res.TokensUsage.CompletionTokens < tokenCount {
		t.Fatalf("expected at least %d tokens, got %v", tokenCount, res.TokensUsage)
	}
	t.Logf("Streamed and accumulated %d tokens in %v", tokenCount, elapsed)
}

// 4. Client disconnect mid-stream: goroutine leak check and status check

type disconnectWriter struct {
	header      http.Header
	flushed     bool
	writeCount  int
	failAfter   int
	disconnect  chan struct{}
}

func (w *disconnectWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *disconnectWriter) Write(b []byte) (int, error) {
	w.writeCount++
	if w.writeCount >= w.failAfter {
		close(w.disconnect)
		return 0, errors.New("client connection closed")
	}
	return len(b), nil
}
func (w *disconnectWriter) WriteHeader(statusCode int) {}
func (w *disconnectWriter) Flush() {
	w.flushed = true
}

func TestAdversarial_ClientDisconnect_MidStream(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	pr, pw := io.Pipe()
	bodyClosed := make(chan struct{})

	// Upstream writer simulator
	go func() {
		defer func() {
			pw.Close()
			close(bodyClosed)
		}()
		for i := 0; i < 50; i++ {
			chunk := fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"part%d \"}}]}\n\n", i)
			if _, err := pw.Write([]byte(chunk)); err != nil {
				// Pipe broken because upstreamBody was closed
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	w := &disconnectWriter{
		failAfter:  5,
		disconnect: make(chan struct{}),
	}
	acc := NewSSEAccumulator()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// When disconnect occurs, cancel context
	go func() {
		<-w.disconnect
		cancel()
	}()

	res, err := p.StreamPassThrough(ctx, w, pr, acc)
	if err == nil {
		t.Fatalf("expected error upon client disconnect")
	}

	if res.Status != "CLIENT_DISCONNECTED" {
		t.Fatalf("expected status 'CLIENT_DISCONNECTED', got '%s'", res.Status)
	}

	// Verify upstream was closed and writer stopped
	select {
	case <-bodyClosed:
		// Upstream properly closed
	case <-time.After(1 * time.Second):
		t.Fatalf("upstreamBody was not closed upon client disconnect")
	}

	// Verify no goroutine leak
	time.Sleep(50 * time.Millisecond)
	currentGoroutines := runtime.NumGoroutine()
	// Allow maximum 2 temporary background goroutines from Go test runner
	if currentGoroutines > initialGoroutines+2 {
		t.Fatalf("potential goroutine leak: initial=%d, current=%d", initialGoroutines, currentGoroutines)
	}
}

// 5. Client Disconnect via Context Cancellation in ServeHTTP

func TestAdversarial_ProxyHandler_ClientDisconnect_AuditEvent(t *testing.T) {
	upstreamHit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		for i := 0; i < 20; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
				_, _ = w.Write([]byte(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"tok%d \"}}]}\n\n", i)))
				flusher.Flush()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(100, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	body := `{"model":"securities-quant-advisor-v1","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
	req.Header.Set("X-Correlation-ID", "corr-disconnect-01")

	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	// Simulate client aborting after 30ms
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if !upstreamHit {
		t.Fatalf("expected upstream to be contacted")
	}

	// Verify ledger queue received envelope with status CLIENT_DISCONNECTED
	select {
	case event := <-queue.Events():
		if event.CorrelationID != "corr-disconnect-01" {
			t.Fatalf("unexpected correlation ID: %s", event.CorrelationID)
		}
		if event.Status != "CLIENT_DISCONNECTED" {
			t.Fatalf("expected audit event status 'CLIENT_DISCONNECTED', got '%s'", event.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for audit event envelope in queue")
	}
}

// 6. Concurrency Stress Test: 50 concurrent streaming & non-streaming clients

func TestAdversarial_Concurrency_Stress(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for j := 0; j < 5; j++ {
			_, _ = w.Write([]byte(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"c%d \"}}]}\n\n", j)))
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rm := registry.NewRegistryManagerWithDefaults()
	queue := ledger.NewBoundedQueue(1000, nil)
	p := NewProxyHandler(DefaultProxyConfig(u), queue, rm, nil)

	concurrentClients := 50
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentClients)

	for i := 0; i < concurrentClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"model":"securities-quant-advisor-v1","messages":[{"role":"user","content":"Stress %d"}],"stream":true}`, idx)
			req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
			req.Header.Set(registry.HeaderAISystemID, "securities-quant-advisor-v1")
			req.Header.Set("X-Correlation-ID", fmt.Sprintf("corr-stress-%d", idx))
			rec := httptest.NewRecorder()

			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				errCh <- fmt.Errorf("client %d got status %d", idx, rec.Code)
				return
			}
			if !strings.Contains(rec.Body.String(), "data: [DONE]") {
				errCh <- fmt.Errorf("client %d missing [DONE]", idx)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency stress failed: %v", err)
	}
}

// 7. Corrupted & Adversarial Chunk Sequence

func TestAdversarial_CorruptedChunks_Resilience(t *testing.T) {
	acc := NewSSEAccumulator()

	// Interleaving garbage, binary bytes, missing quotes, random lines
	corrupted := []string{
		": keep-alive comment\n\n",
		"data: \n\n",
		"data: {\"incomplete\":\n\n",
		"data: not_even_json\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"Real \"}}]}\n\n",
		": another comment\n\n",
		"\x00\x01\x02\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"Data\"}}]}\n\n",
		"data: [DONE]\n\n",
	}

	for _, c := range corrupted {
		acc.ProcessBytes([]byte(c))
	}

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Real Data" {
		t.Fatalf("expected 'Real Data', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
}

