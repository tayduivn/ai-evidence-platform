package config

import (
	"os"
	"testing"
)

func TestConfig_Defaults(t *testing.T) {
	os.Unsetenv("GATEWAY_PORT")
	os.Unsetenv("UPSTREAM_LLM_URL")
	os.Unsetenv("LEDGER_QUEUE_CAPACITY")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Port != 8080 {
		t.Fatalf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.UpstreamLLMURL.String() != "http://127.0.0.1:8000" {
		t.Fatalf("expected default upstream URL http://127.0.0.1:8000, got %s", cfg.UpstreamLLMURL.String())
	}
	if cfg.LedgerQueueCapacity != 50000 {
		t.Fatalf("expected default queue capacity 50000, got %d", cfg.LedgerQueueCapacity)
	}
}

func TestConfig_EnvOverrides(t *testing.T) {
	os.Setenv("GATEWAY_PORT", "9090")
	os.Setenv("UPSTREAM_LLM_URL", "http://llm.cluster.local:8080")
	os.Setenv("LEDGER_QUEUE_CAPACITY", "10000")
	defer func() {
		os.Unsetenv("GATEWAY_PORT")
		os.Unsetenv("UPSTREAM_LLM_URL")
		os.Unsetenv("LEDGER_QUEUE_CAPACITY")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.Port)
	}
	if cfg.UpstreamLLMURL.String() != "http://llm.cluster.local:8080" {
		t.Fatalf("expected http://llm.cluster.local:8080, got %s", cfg.UpstreamLLMURL.String())
	}
	if cfg.LedgerQueueCapacity != 10000 {
		t.Fatalf("expected capacity 10000, got %d", cfg.LedgerQueueCapacity)
	}
}
