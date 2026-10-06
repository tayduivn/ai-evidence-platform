package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewRouter constructs a Chi HTTP router with standard middleware and routes.
func NewRouter(service *Service, uiHandler http.Handler) http.Handler {
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	// Liveness & Readiness probes
	r.Get("/health", HealthHandler(service))
	r.Get("/ready", ReadyHandler(service))

	// Approval REST API v1
	r.Route("/api/v1/approvals", func(r chi.Router) {
		r.Get("/pending", ListPendingApprovalsHandler(service))
		r.Get("/{id}", GetApprovalDetailHandler(service))
		r.Post("/{id}/dwell", RecordDwellHeartbeatHandler(service))
		r.Post("/{id}/decide", SubmitDecisionActionHandler(service))
	})

	// Embedded Web UI Handler
	if uiHandler != nil {
		r.Handle("/*", uiHandler)
	}

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, X-AI-System-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
