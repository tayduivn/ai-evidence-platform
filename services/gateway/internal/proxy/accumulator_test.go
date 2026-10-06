package proxy

import (
	"strings"
	"testing"
)

func TestAccumulator_MultiChunk(t *testing.T) {
	acc := NewSSEAccumulator()
	chunks := []string{
		"data: {\"id\":\"chk-1\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
		"data: {\"id\":\"chk-1\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
		"data: {\"id\":\"chk-1\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}]}\n\n",
		"data: [DONE]\n\n",
	}

	for _, c := range chunks {
		acc.ProcessBytes([]byte(c))
	}

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Hello world!" {
		t.Fatalf("expected 'Hello world!', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
	if res.Model != "gpt-4o" {
		t.Fatalf("expected model gpt-4o, got %s", res.Model)
	}
	if res.FinishReason != "stop" {
		t.Fatalf("expected finishReason stop, got %s", res.FinishReason)
	}
	if res.TokensUsage == nil || res.TokensUsage.CompletionTokens <= 0 {
		t.Fatalf("expected positive completion tokens, got %v", res.TokensUsage)
	}
}

func TestAccumulator_SplitLines(t *testing.T) {
	acc := NewSSEAccumulator()
	// Split chunk across JSON boundary
	chunk1 := "data: {\"id\":\"chk-1\",\"choices\":[{\"delta\":{\"con"
	chunk2 := "tent\":\"Split token test\"}}]}\n\n"
	chunk3 := "data: [DONE]\n\n"

	acc.ProcessBytes([]byte(chunk1))
	acc.ProcessBytes([]byte(chunk2))
	acc.ProcessBytes([]byte(chunk3))

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Split token test" {
		t.Fatalf("expected 'Split token test', got '%s'", res.AssembledText)
	}
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
}

func TestAccumulator_DoneSentinel(t *testing.T) {
	acc := NewSSEAccumulator()
	acc.ProcessBytes([]byte("data: [DONE]\n\n"))
	res := acc.Finalize("COMPLETED")
	if !res.IsDoneReceived {
		t.Fatalf("expected isDoneReceived = true")
	}
	if res.AssembledText != "" {
		t.Fatalf("expected empty assembled text, got '%s'", res.AssembledText)
	}
}

func TestAccumulator_EmptyStream(t *testing.T) {
	acc := NewSSEAccumulator()
	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "" {
		t.Fatalf("expected empty text, got '%s'", res.AssembledText)
	}
	if res.TokensUsage.CompletionTokens != 0 {
		t.Fatalf("expected 0 tokens, got %d", res.TokensUsage.CompletionTokens)
	}
}

func TestAccumulator_SingleToken(t *testing.T) {
	acc := NewSSEAccumulator()
	acc.ProcessBytes([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n"))
	acc.ProcessBytes([]byte("data: [DONE]\n\n"))
	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "OK" {
		t.Fatalf("expected 'OK', got '%s'", res.AssembledText)
	}
	if res.TokensUsage.CompletionTokens != 1 {
		t.Fatalf("expected 1 token, got %d", res.TokensUsage.CompletionTokens)
	}
}

func TestAccumulator_MalformedJSON(t *testing.T) {
	acc := NewSSEAccumulator()
	acc.ProcessBytes([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Valid \"}}]}\n\n"))
	acc.ProcessBytes([]byte("data: {MALFORMED_JSON\n\n"))
	acc.ProcessBytes([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"token\"}}]}\n\n"))
	acc.ProcessBytes([]byte("data: [DONE]\n\n"))

	res := acc.Finalize("COMPLETED")
	if res.AssembledText != "Valid token" {
		t.Fatalf("expected 'Valid token', got '%s'", res.AssembledText)
	}
}

func TestAccumulator_ClientAborted(t *testing.T) {
	acc := NewSSEAccumulator()
	acc.ProcessBytes([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Partial content\"}}]}\n\n"))

	res := acc.Finalize("CLIENT_DISCONNECTED")
	if res.Status != "CLIENT_DISCONNECTED" {
		t.Fatalf("expected status CLIENT_DISCONNECTED, got %s", res.Status)
	}
	if !strings.Contains(res.AssembledText, "Partial content") {
		t.Fatalf("expected partial content preserved, got '%s'", res.AssembledText)
	}
}

func TestAccumulator_UnboundedLineProtection(t *testing.T) {
	acc := NewSSEAccumulator()
	// Feed 2MB of non-delimited data (no newline)
	largeChunk := make([]byte, 2*1024*1024)
	for i := range largeChunk {
		largeChunk[i] = 'A'
	}
	acc.ProcessBytes(largeChunk)

	// Verify buffer did not crash and remained bounded
	acc.mu.Lock()
	bufLen := acc.lineBuffer.Len()
	acc.mu.Unlock()

	if bufLen > maxLineBufferSize {
		t.Fatalf("expected buffer length <= %d, got %d", maxLineBufferSize, bufLen)
	}
}
