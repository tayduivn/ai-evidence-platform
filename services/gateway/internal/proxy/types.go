package proxy

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/ledger"
)

// ProxyConfig defines runtime parameters for the Reverse Proxy engine.
type ProxyConfig struct {
	UpstreamURL         *url.URL      // Target upstream LLM base URL (default: http://127.0.0.1:8000)
	UpstreamTimeout     time.Duration // Max duration for upstream communication (default: 60s)
	IdleConnTimeout     time.Duration // Idle connection timeout in connection pool (default: 90s)
	MaxIdleConns        int           // Max idle connections across all hosts (default: 100)
	MaxIdleConnsPerHost int           // Max idle connections per host (default: 50)
	ChunkBufferSize     int           // Read buffer size for streaming chunks (default: 4096 bytes)
}

// DefaultProxyConfig returns production-tuned defaults for the proxy engine.
func DefaultProxyConfig(upstream *url.URL) ProxyConfig {
	return ProxyConfig{
		UpstreamURL:         upstream,
		UpstreamTimeout:     60 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		ChunkBufferSize:     4096,
	}
}

// ProxyHandler encapsulates the HTTP reverse proxy, flusher, and ledger dispatcher.
type ProxyHandler struct {
	cfg           ProxyConfig
	transport     *http.Transport
	client        *http.Client
	queue         ledger.LedgerQueue
	registry      *registry.RegistryManager
	decisionStore dualmode.DecisionStore
	bufferPool    *sync.Pool
}

// NewProxyHandler constructs an initialized ProxyHandler.
func NewProxyHandler(
	cfg ProxyConfig,
	queue ledger.LedgerQueue,
	rm *registry.RegistryManager,
	store dualmode.DecisionStore,
) *ProxyHandler {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.UpstreamTimeout,
	}

	pool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, cfg.ChunkBufferSize)
			return &buf
		},
	}

	return &ProxyHandler{
		cfg:           cfg,
		transport:     transport,
		client:        client,
		queue:         queue,
		registry:      rm,
		decisionStore: store,
		bufferPool:    pool,
	}
}
