package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAdversarial_Registry_HeaderAttacks tests adversarial attacks against AI Registry headers.
func TestAdversarial_Registry_HeaderAttacks(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	handler := rm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"AUTHORIZED"}`))
	}))

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Whitespace_Padding_Around_Registered_ID",
			headers: map[string]string{
				"X-AI-System-ID": "   credit-advisor-v1   ",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Header_Casing_Lowercase",
			headers: map[string]string{
				"x-ai-system-id": "credit-advisor-v1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Header_Casing_Uppercase",
			headers: map[string]string{
				"X-AI-SYSTEM-ID": "credit-advisor-v1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Header_Casing_Mixed",
			headers: map[string]string{
				"x-Ai-SyStEm-Id": "credit-advisor-v1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Empty_Header_Value",
			headers: map[string]string{
				"X-AI-System-ID": "",
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Missing X-AI-System-ID header: Shadow AI detected",
		},
		{
			name: "Whitespace_Only_Header_Value",
			headers: map[string]string{
				"X-AI-System-ID": "    \t \n  ",
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Missing X-AI-System-ID header: Shadow AI detected",
		},
		{
			name:           "Missing_Header_Completely",
			headers:        map[string]string{},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Missing X-AI-System-ID header: Shadow AI detected",
		},
		{
			name: "Shadow_AI_Unregistered_System_ID",
			headers: map[string]string{
				"X-AI-System-ID": "unauthorized-shadow-agent-v9",
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Unregistered AI system 'unauthorized-shadow-agent-v9': Shadow AI rejected",
		},
		{
			name: "Artifact_Hash_Tampering_Attack",
			headers: map[string]string{
				"X-AI-System-ID":     "credit-scoring-xgboost",
				"X-AI-Artifact-Hash": "malicious_tampered_artifact_hash_666",
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Artifact hash mismatch: Model tampering detected",
		},
		{
			name: "Prompt_Hash_Tampering_Attack",
			headers: map[string]string{
				"X-AI-System-ID":   "credit-advisor-v1",
				"X-AI-Prompt-Hash": "injected_jailbreak_prompt_hash",
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Prompt hash mismatch: Unauthorized prompt modification",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Fatalf("expected status %d, got %d. Body: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}

			if tc.expectedError != "" {
				var errResp ErrorResponse
				if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if !strings.Contains(errResp.Error, tc.expectedError) {
					t.Fatalf("expected error '%s', got '%s'", tc.expectedError, errResp.Error)
				}
			}
		})
	}
}
