package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"ei-evidence-platform/services/ledger"
)

// AccumulatorResult contains the final assembled text, token counts, and completion status.
type AccumulatorResult struct {
	Model             string             `json:"model"`
	CompletionID      string             `json:"completion_id"`
	AssembledText     string             `json:"assembled_text"`
	JSONOutputPayload string             `json:"json_output_payload"`
	TokensUsage       *ledger.TokenUsage `json:"tokens_usage"`
	Status            string             `json:"status"`
	FinishReason      string             `json:"finish_reason,omitempty"`
	IsDoneReceived    bool               `json:"is_done_received"`
}

// SSEAccumulator buffers lines and parses tokens across arbitrary TCP chunk boundaries.
type SSEAccumulator struct {
	mu           sync.Mutex
	lineBuffer   bytes.Buffer
	textBuilder  strings.Builder
	model        string
	completionID string
	finishReason string
	upstreamUsage *ledger.TokenUsage
	isDone       bool
}

// NewSSEAccumulator constructs a fresh SSEAccumulator.
func NewSSEAccumulator() *SSEAccumulator {
	return &SSEAccumulator{}
}

const maxLineBufferSize = 1024 * 1024 // 1 MB safety ceiling for SSE line buffer

// ProcessBytes feeds raw stream chunk bytes into the line buffer and extracts tokens.
func (a *SSEAccumulator) ProcessBytes(chunk []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Guard against unbounded lineBuffer memory consumption from malformed streams lacking newlines
	if a.lineBuffer.Len() > maxLineBufferSize {
		a.lineBuffer.Reset()
	}

	a.lineBuffer.Write(chunk)

	for {
		line, err := a.lineBuffer.ReadBytes('\n')
		if err != nil {
			// Incomplete line remaining in buffer: restore unread bytes if within safe ceiling
			if len(line) <= maxLineBufferSize {
				a.lineBuffer.Write(line)
			}
			break
		}

		a.processLine(line)
	}
}

// processLine parses an individual SSE event line.
func (a *SSEAccumulator) processLine(rawLine []byte) {
	line := strings.TrimSpace(string(rawLine))
	if len(line) == 0 || strings.HasPrefix(line, ":") {
		return // Empty keep-alive line or SSE comment
	}

	if !strings.HasPrefix(line, "data: ") {
		return
	}

	dataContent := strings.TrimPrefix(line, "data: ")
	if dataContent == "[DONE]" {
		a.isDone = true
		return
	}

	var chunk ChatCompletionChunk
	if err := json.Unmarshal([]byte(dataContent), &chunk); err != nil {
		// Ignore malformed chunk without aborting stream assembly
		return
	}

	if chunk.Model != "" && a.model == "" {
		a.model = chunk.Model
	}
	if chunk.ID != "" && a.completionID == "" {
		a.completionID = chunk.ID
	}
	if chunk.Usage != nil {
		a.upstreamUsage = chunk.Usage
	}

	for _, choice := range chunk.Choices {
		if choice.Delta.Content != "" {
			a.textBuilder.WriteString(choice.Delta.Content)
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			a.finishReason = *choice.FinishReason
		}
	}
}

// Finalize flushes any remaining buffered text and produces the completed AccumulatorResult.
func (a *SSEAccumulator) Finalize(status string) AccumulatorResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Flush any trailing line without newline
	if a.lineBuffer.Len() > 0 {
		trailing := a.lineBuffer.Bytes()
		a.processLine(trailing)
		a.lineBuffer.Reset()
	}

	assembled := a.textBuilder.String()

	usage := a.upstreamUsage
	if usage == nil {
		completionTokens := estimateTokenCount(assembled)
		usage = &ledger.TokenUsage{
			PromptTokens:     0,
			CompletionTokens: completionTokens,
			TotalTokens:      completionTokens,
		}
	}

	outputObj := map[string]string{"response": assembled}
	outputJSON, _ := json.Marshal(outputObj)

	return AccumulatorResult{
		Model:             a.model,
		CompletionID:      a.completionID,
		AssembledText:     assembled,
		JSONOutputPayload: string(outputJSON),
		TokensUsage:       usage,
		Status:            status,
		FinishReason:      a.finishReason,
		IsDoneReceived:    a.isDone,
	}
}

func estimateTokenCount(text string) int {
	words := strings.Fields(text)
	if len(words) == 0 {
		return 0
	}
	tokens := int(float64(len(words)) * 1.3)
	if tokens < 1 && len(text) > 0 {
		return 1
	}
	return tokens
}
