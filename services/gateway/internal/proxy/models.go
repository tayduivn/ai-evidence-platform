package proxy

import "ei-evidence-platform/services/ledger"

// ChatMessage represents a single message in the chat conversation.
type ChatMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string or []interface{}
}

// ChatCompletionRequest models the standard OpenAI chat completions request.
type ChatCompletionRequest struct {
	Model            string        `json:"model"`
	Messages         []ChatMessage `json:"messages"`
	Stream           bool          `json:"stream,omitempty"`
	Temperature      *float64      `json:"temperature,omitempty"`
	TopP             *float64      `json:"top_p,omitempty"`
	MaxTokens        *int          `json:"max_tokens,omitempty"`
	RequiresApproval *bool         `json:"requires_approval,omitempty"`
}

// ChunkDelta represents the incremental token payload in an SSE chunk.
type ChunkDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// ChunkChoice represents a single choice in a streaming chunk.
type ChunkChoice struct {
	Index        int        `json:"index"`
	Delta        ChunkDelta `json:"delta"`
	FinishReason *string    `json:"finish_reason,omitempty"`
}

// ChatCompletionChunk models an individual SSE data chunk emitted by OpenAI-compatible LLMs.
type ChatCompletionChunk struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Created int64                `json:"created"`
	Model   string               `json:"model"`
	Choices []ChunkChoice        `json:"choices"`
	Usage   *ledger.TokenUsage   `json:"usage,omitempty"`
}

// NonStreamingChoice models choices in a standard non-streaming response.
type NonStreamingChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatCompletionResponse models a standard non-streaming chat completion response.
type ChatCompletionResponse struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Created int64                `json:"created"`
	Model   string               `json:"model"`
	Choices []NonStreamingChoice `json:"choices"`
	Usage   *ledger.TokenUsage   `json:"usage,omitempty"`
}

// OpenAIErrorBody matches the standard OpenAI JSON error schema.
type OpenAIErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    int    `json:"code"`
}

// OpenAIErrorResponse wraps OpenAIErrorBody under the "error" root key.
type OpenAIErrorResponse struct {
	Error OpenAIErrorBody `json:"error"`
}
