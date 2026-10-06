package server

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the standard probe response for /health and /ready.
type HealthResponse struct {
	Status string `json:"status"`
}

// HealthHandler returns HTTP 200 with status UP.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: "UP"})
}

// ReadyHandler returns HTTP 200 with status READY.
func ReadyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(HealthResponse{Status: "READY"})
}
