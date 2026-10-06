package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Server wraps http.Server with graceful shutdown capabilities.
type Server struct {
	httpServer *http.Server
}

// NewServer initializes an HTTP server on the specified port.
func NewServer(port int, handler http.Handler) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 90 * time.Second, // Allow extended streaming durations
			IdleTimeout:  120 * time.Second,
		},
	}
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully terminates in-flight connections within the given timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the configured address.
func (s *Server) Addr() string {
	return s.httpServer.Addr
}
