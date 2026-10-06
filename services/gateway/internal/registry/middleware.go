package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware enforcing AI Registry verification on incoming requests.
func (rm *RegistryManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		systemID := strings.TrimSpace(r.Header.Get(HeaderAISystemID))
		artifactHash := strings.TrimSpace(r.Header.Get(HeaderAIArtifactHash))
		promptHash := strings.TrimSpace(r.Header.Get(HeaderAIPromptHash))

		status, errMsg, entry := rm.EvaluateRequest(systemID, artifactHash, promptHash)
		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(ErrorResponse{
				Error: errMsg,
			})
			return
		}

		ctx := context.WithValue(r.Context(), SystemEntryContextKey, *entry)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
