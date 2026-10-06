package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/mlingest"
	"ei-evidence-platform/services/gateway/internal/proxy"
)

// RouterOptions holds dependencies required to assemble the router.
type RouterOptions struct {
	ProxyHandler    *proxy.ProxyHandler
	IngestHandler   *mlingest.IngestHandler
	DecisionStore   dualmode.DecisionStore
}

// NewRouter constructs and configures the HTTP router with routes and middleware.
func NewRouter(opts RouterOptions) http.Handler {
	r := chi.NewRouter()

	// Global Middleware
	r.Use(Recoverer)
	r.Use(CorrelationID)
	r.Use(RealIP)
	r.Use(AccessLogger)

	// Health Probes
	r.Get("/health", HealthHandler)
	r.Get("/ready", ReadyHandler)

	// Reverse Proxy for Chat Completions
	if opts.ProxyHandler != nil {
		r.Post("/v1/chat/completions", opts.ProxyHandler.ServeHTTP)
		r.Post("/chat/completions", opts.ProxyHandler.ServeHTTP)
	}

	// ML Ingest API
	if opts.IngestHandler != nil {
		r.Post("/api/v1/ml/ingest", opts.IngestHandler.ServeHTTP)
	}

	// Human-in-the-Loop Decision Status Polling
	if opts.DecisionStore != nil {
		r.Get("/api/v1/decisions/{id}/status", dualmode.NewDecisionStatusHandler(opts.DecisionStore))
	}

	return r
}
