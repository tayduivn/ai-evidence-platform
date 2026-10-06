package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

func TestRegistry_MissingHeader_403ShadowAIDetected(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	status, msg, entry := rm.EvaluateRequest("", "", "")
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
	expectedMsg := "Missing X-AI-System-ID header: Shadow AI detected"
	if msg != expectedMsg {
		t.Fatalf("expected message '%s', got '%s'", expectedMsg, msg)
	}
	if entry != nil {
		t.Fatalf("expected nil entry for rejected request")
	}
}

func TestRegistry_UnregisteredID_403ShadowAIRejected(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	systemID := "shadow-rogue-copilot"
	status, msg, entry := rm.EvaluateRequest(systemID, "", "")
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
	expectedMsg := "Unregistered AI system 'shadow-rogue-copilot': Shadow AI rejected"
	if msg != expectedMsg {
		t.Fatalf("expected message '%s', got '%s'", expectedMsg, msg)
	}
	if entry != nil {
		t.Fatalf("expected nil entry for rejected request")
	}
}

func TestRegistry_ValidSystem_200Authorized(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	status, msg, entry := rm.EvaluateRequest("credit-advisor-v1", "", "")
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
	if msg != "AUTHORIZED" {
		t.Fatalf("expected message 'AUTHORIZED', got '%s'", msg)
	}
	if entry == nil || entry.SystemID != "credit-advisor-v1" {
		t.Fatalf("expected entry for credit-advisor-v1, got %v", entry)
	}
}

func TestRegistry_ArtifactHashMismatch_403TamperingDetected(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	status, msg, _ := rm.EvaluateRequest(
		"credit-scoring-xgboost",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"",
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
	expectedMsg := "Artifact hash mismatch: Model tampering detected"
	if msg != expectedMsg {
		t.Fatalf("expected message '%s', got '%s'", expectedMsg, msg)
	}
}

func TestRegistry_PromptHashMismatch_403UnauthorizedModification(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	status, msg, _ := rm.EvaluateRequest(
		"credit-advisor-v1",
		"",
		"tampered_unauthorized_prompt_hash",
	)
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
	expectedMsg := "Prompt hash mismatch: Unauthorized prompt modification"
	if msg != expectedMsg {
		t.Fatalf("expected message '%s', got '%s'", expectedMsg, msg)
	}
}

func TestRegistry_ConcurrentAccess_RaceFree(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _, _ = rm.EvaluateRequest("credit-advisor-v1", "", "")
			_, _ = rm.Get("securities-quant-advisor-v1")
		}(i)
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rm.Register(SystemEntry{
				SystemID:   "dynamic-model-test",
				RiskLevel:  "LOW",
				SystemType: "ml",
			})
		}(i)
	}

	wg.Wait()
}

func TestRegistry_Middleware(t *testing.T) {
	rm := NewRegistryManagerWithDefaults()
	handler := rm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry, ok := r.Context().Value(SystemEntryContextKey).(SystemEntry)
		if !ok {
			http.Error(w, "missing context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"system_id": entry.SystemID})
	}))

	// 1. Missing header
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var errResp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp.Error != "Missing X-AI-System-ID header: Shadow AI detected" {
		t.Fatalf("unexpected error response: %v", errResp)
	}

	// 2. Authorized system
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderAISystemID, "credit-advisor-v1")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var okResp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &okResp)
	if okResp["system_id"] != "credit-advisor-v1" {
		t.Fatalf("unexpected system_id: %s", okResp["system_id"])
	}
}

func TestRegistry_LoadFromFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "registry_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `{
		"systems": [
			{
				"system_id": "file-loaded-model-01",
				"model_version": "v3.0",
				"risk_level": "MEDIUM",
				"requires_approval": false
			}
		]
	}`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	rm := NewRegistryManager()
	if err := rm.LoadFromFile(tmpFile.Name()); err != nil {
		t.Fatalf("unexpected error loading from file: %v", err)
	}

	entry, exists := rm.Get("file-loaded-model-01")
	if !exists || entry.SystemID != "file-loaded-model-01" {
		t.Fatalf("expected loaded system entry, got %+v", entry)
	}

	// Test non-existent file
	if err := rm.LoadFromFile("non_existent_file.json"); err == nil {
		t.Fatalf("expected error loading non-existent file")
	}

	// Test invalid JSON file
	badFile, _ := os.CreateTemp("", "bad_*.json")
	defer os.Remove(badFile.Name())
	_, _ = badFile.WriteString("{bad json")
	badFile.Close()
	if err := rm.LoadFromFile(badFile.Name()); err == nil {
		t.Fatalf("expected error loading invalid JSON file")
	}
}

