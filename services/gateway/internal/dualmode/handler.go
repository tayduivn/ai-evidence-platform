package dualmode

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DecisionStatusResponse is the JSON payload returned on GET /api/v1/decisions/{id}/status.
type DecisionStatusResponse struct {
	DecisionID    string `json:"decision_id"`
	Status        string `json:"status"`
	CorrelationID string `json:"correlation_id,omitempty"`
	AISystemID    string `json:"ai_system_id,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// NewDecisionStatusHandler creates an HTTP handler for GET /api/v1/decisions/{id}/status.
func NewDecisionStatusHandler(store DecisionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id == "" {
			// Fallback: extract from path /api/v1/decisions/{id}/status
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			for i, p := range parts {
				if p == "decisions" && i+1 < len(parts) {
					id = parts[i+1]
					break
				}
			}
		}

		if id == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing decision ID"})
			return
		}

		record, err := store.Get(id)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Decision not found"})
			return
		}

		resp := DecisionStatusResponse{
			DecisionID:    record.DecisionID,
			Status:        record.Status,
			CorrelationID: record.CorrelationID,
			AISystemID:    record.AISystemID,
			CreatedAt:     record.CreatedAt.Format("2006-01-02T15:04:05.999999Z"),
			UpdatedAt:     record.UpdatedAt.Format("2006-01-02T15:04:05.999999Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
