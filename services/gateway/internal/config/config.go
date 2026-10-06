package config

import (
	"net/url"
	"os"
	"strconv"
)

// Config holds runtime configuration options for the Gateway service.
type Config struct {
	Port                int      `json:"port"`
	UpstreamLLMURL      *url.URL `json:"upstream_llm_url"`
	LedgerQueueCapacity int      `json:"ledger_queue_capacity"`
	RegistryFilePath    string   `json:"registry_file_path,omitempty"`
}

// LoadConfig populates configuration from environment variables with fallback defaults.
func LoadConfig() (*Config, error) {
	port := 8080
	if envPort := os.Getenv("GATEWAY_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			port = p
		}
	}

	upstreamStr := "http://127.0.0.1:8000"
	if envUpstream := os.Getenv("UPSTREAM_LLM_URL"); envUpstream != "" {
		upstreamStr = envUpstream
	}
	upstreamURL, err := url.Parse(upstreamStr)
	if err != nil {
		return nil, err
	}

	capacity := 50000
	if envCap := os.Getenv("LEDGER_QUEUE_CAPACITY"); envCap != "" {
		if c, err := strconv.Atoi(envCap); err == nil && c > 0 {
			capacity = c
		}
	}

	regPath := os.Getenv("REGISTRY_FILE_PATH")

	return &Config{
		Port:                port,
		UpstreamLLMURL:      upstreamURL,
		LedgerQueueCapacity: capacity,
		RegistryFilePath:    regPath,
	}, nil
}
