package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type nonFlusherWriter struct {
	header http.Header
	buf    bytes.Buffer
	code   int
}

func (w *nonFlusherWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *nonFlusherWriter) Write(b []byte) (int, error) {
	return w.buf.Write(b)
}
func (w *nonFlusherWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

func TestSSEFlusher_ChunkPassThrough(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	streamData := "data: {\"choices\":[{\"delta\":{\"content\":\"Chunk1\"}}]}\n\ndata: [DONE]\n\n"
	body := io.NopCloser(strings.NewReader(streamData))

	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	if err != nil {
		t.Fatalf("unexpected streaming error: %v", err)
	}

	if rec.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("unexpected content-type: %s", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("unexpected cache-control: %s", rec.Header().Get("Cache-Control"))
	}

	if res.AssembledText != "Chunk1" {
		t.Fatalf("expected assembled text 'Chunk1', got '%s'", res.AssembledText)
	}
	if !rec.Flushed {
		t.Fatalf("expected response to be flushed")
	}
}

func TestSSEFlusher_BurstRate(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")

	body := io.NopCloser(strings.NewReader(sb.String()))
	rec := httptest.NewRecorder()
	acc := NewSSEAccumulator()

	res, err := p.StreamPassThrough(context.Background(), rec, body, acc)
	if err != nil {
		t.Fatalf("unexpected error in burst stream: %v", err)
	}

	if len(res.AssembledText) != 50 {
		t.Fatalf("expected 50 chars in burst, got %d", len(res.AssembledText))
	}
}

func TestSSEFlusher_NoFlusherSupported(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:8000")
	p := NewProxyHandler(DefaultProxyConfig(u), nil, nil, nil)

	body := io.NopCloser(strings.NewReader("data: test\n\n"))
	w := &nonFlusherWriter{}
	acc := NewSSEAccumulator()

	_, err := p.StreamPassThrough(context.Background(), w, body, acc)
	if err == nil {
		t.Fatalf("expected error when ResponseWriter lacks flusher")
	}
	if w.code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.code)
	}
}
