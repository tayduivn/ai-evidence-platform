package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

// RegistryManager manages thread-safe registry operations and access evaluation.
type RegistryManager struct {
	mu      sync.RWMutex
	systems map[string]SystemEntry
}

// NewRegistryManager creates an empty RegistryManager.
func NewRegistryManager() *RegistryManager {
	return &RegistryManager{
		systems: make(map[string]SystemEntry),
	}
}

// NewRegistryManagerWithDefaults creates a RegistryManager preloaded with seed systems.
func NewRegistryManagerWithDefaults() *RegistryManager {
	rm := NewRegistryManager()
	rm.Register(SystemEntry{
		SystemID:           "credit-advisor-v1",
		ModelVersion:       "gpt-4o-2024-08-06",
		RiskLevel:          "HIGH",
		SystemType:         "llm",
		RequiresApproval:   true,
		ExpectedPromptHash: "a1b2c3d4",
		Owner:              "risk-engineering",
	})
	rm.Register(SystemEntry{
		SystemID:         "securities-quant-advisor-v1",
		ModelVersion:     "gpt-4o",
		RiskLevel:        "HIGH",
		SystemType:       "llm",
		RequiresApproval: false,
		Owner:            "quant-trading",
	})
	rm.Register(SystemEntry{
		SystemID:         "credit-scoring-xgboost",
		ModelVersion:     "v2.1.0",
		RiskLevel:        "CRITICAL",
		SystemType:       "ml",
		ArtifactHash:     "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		RequiresApproval: true,
		Owner:            "fintech-credit",
	})
	return rm
}

// Register adds or updates an AI system entry in the registry.
func (rm *RegistryManager) Register(entry SystemEntry) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.systems[entry.SystemID] = entry
}

// Get retrieves a system entry by its unique system ID.
func (rm *RegistryManager) Get(systemID string) (SystemEntry, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	entry, exists := rm.systems[systemID]
	return entry, exists
}

// LoadFromFile loads registered systems from a JSON file.
func (rm *RegistryManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var wrapper struct {
		Systems []SystemEntry `json:"systems"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, sys := range wrapper.Systems {
		rm.systems[sys.SystemID] = sys
	}
	return nil
}

// EvaluateRequest enforces registry access rules, model tampering checks, and prompt integrity.
func (rm *RegistryManager) EvaluateRequest(systemID, artifactHash, promptHash string) (int, string, *SystemEntry) {
	if systemID == "" {
		return http.StatusForbidden, "Missing X-AI-System-ID header: Shadow AI detected", nil
	}

	entry, exists := rm.Get(systemID)
	if !exists {
		return http.StatusForbidden, fmt.Sprintf("Unregistered AI system '%s': Shadow AI rejected", systemID), nil
	}

	if artifactHash != "" && entry.ArtifactHash != "" && artifactHash != entry.ArtifactHash {
		return http.StatusForbidden, "Artifact hash mismatch: Model tampering detected", nil
	}

	if promptHash != "" && entry.ExpectedPromptHash != "" && promptHash != entry.ExpectedPromptHash {
		return http.StatusForbidden, "Prompt hash mismatch: Unauthorized prompt modification", nil
	}

	return http.StatusOK, "AUTHORIZED", &entry
}
