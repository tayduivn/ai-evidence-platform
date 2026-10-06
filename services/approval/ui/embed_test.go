package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetHandler_ServesEmbeddedFiles(t *testing.T) {
	handler := AssetHandler()

	tests := []struct {
		name         string
		path         string
		expectedCode int
		expectedBody string
	}{
		{"root index", "/", http.StatusOK, "BẢO CHỨNG QUYẾT ĐỊNH AI"},
		{"app css", "/app.css", http.StatusOK, "--bg-primary"},
		{"app js", "/app.js", http.StatusOK, "loadPendingQueue"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Fatalf("expected status %d for %s, got %d", tt.expectedCode, tt.path, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tt.expectedBody) {
				t.Fatalf("expected body of %s to contain %q, but got %q", tt.path, tt.expectedBody, rec.Body.String())
			}
		})
	}
}

func TestAssetHandler_AppJS_DynamicDwellAndSessionToken(t *testing.T) {
	handler := AssetHandler()
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	if !strings.Contains(body, `session_token: "web-session-active"`) {
		t.Errorf("expected app.js to contain session_token: \"web-session-active\"")
	}

	if strings.Contains(body, "dwell_seconds: 15") {
		t.Errorf("app.js must not contain hardcoded dwell_seconds: 15")
	}

	if !strings.Contains(body, "Math.max(minDwell, dwellElapsedSecs)") {
		t.Errorf("expected app.js to calculate dwell_seconds via Math.max(minDwell, dwellElapsedSecs)")
	}

	if !strings.Contains(body, "dwellElapsedSecs++") {
		t.Errorf("expected app.js to track dwellElapsedSecs during timer interval")
	}
}

