package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ei-evidence-platform/services/gateway/internal/config"
	"ei-evidence-platform/services/gateway/internal/dualmode"
	"ei-evidence-platform/services/gateway/internal/mlingest"
	"ei-evidence-platform/services/gateway/internal/proxy"
	"ei-evidence-platform/services/gateway/internal/registry"
	"ei-evidence-platform/services/gateway/internal/server"
	"ei-evidence-platform/services/ledger"
)

func main() {
	log.Println("[GATEWAY] Starting AI Reverse Proxy Gateway & ML Ingest Service...")

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[GATEWAY] Failed to load configuration: %v", err)
	}

	// 2. Initialize Ledger Queue
	queue := ledger.NewBoundedQueue(cfg.LedgerQueueCapacity, nil)
	log.Printf("[GATEWAY] In-memory micro-batch queue initialized (capacity: %d)", cfg.LedgerQueueCapacity)

	// 3. Initialize AI Registry
	rm := registry.NewRegistryManagerWithDefaults()
	if cfg.RegistryFilePath != "" {
		if err := rm.LoadFromFile(cfg.RegistryFilePath); err != nil {
			log.Printf("[GATEWAY] Warning: failed to load registry file %s: %v", cfg.RegistryFilePath, err)
		} else {
			log.Printf("[GATEWAY] Loaded AI Registry systems from %s", cfg.RegistryFilePath)
		}
	}

	// 4. Initialize Decision Store
	decisionStore := dualmode.NewMemoryDecisionStore()

	// 5. Initialize Handlers
	proxyCfg := proxy.DefaultProxyConfig(cfg.UpstreamLLMURL)
	proxyHandler := proxy.NewProxyHandler(proxyCfg, queue, rm, decisionStore)
	ingestHandler := mlingest.NewIngestHandler(queue, rm, decisionStore)

	// 6. Assemble Router
	router := server.NewRouter(server.RouterOptions{
		ProxyHandler:  proxyHandler,
		IngestHandler: ingestHandler,
		DecisionStore: decisionStore,
	})

	srv := server.NewServer(cfg.Port, router)

	// 7. Start HTTP Server in background
	go func() {
		log.Printf("[GATEWAY] Server listening on %s (upstream: %s)", srv.Addr(), cfg.UpstreamLLMURL.String())
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[GATEWAY] Server error: %v", err)
		}
	}()

	// 8. Graceful Shutdown Signal Trapping
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[GATEWAY] Received signal %v, initiating graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[GATEWAY] HTTP shutdown error: %v", err)
	}

	if err := queue.Close(); err != nil {
		log.Printf("[GATEWAY] Queue close error: %v", err)
	}

	log.Println("[GATEWAY] Gateway stopped cleanly.")
}
