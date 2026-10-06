package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"ei-evidence-platform/services/approval/internal/api"
	"ei-evidence-platform/services/approval/internal/dwell"
	"ei-evidence-platform/services/approval/internal/fourofeyes"
	"ei-evidence-platform/services/approval/internal/lifecycle"
	"ei-evidence-platform/services/approval/internal/signer"
	"ei-evidence-platform/services/approval/ui"
	"ei-evidence-platform/services/ledger"
)

func main() {
	log.Println("[APPROVAL] Starting Human-in-the-Loop Approval UI & Pluggable Signer Service...")

	// 1. Port & Configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	queueCap := 1000
	if qEnv := os.Getenv("LEDGER_QUEUE_CAPACITY"); qEnv != "" {
		if parsed, err := strconv.Atoi(qEnv); err == nil && parsed > 0 {
			queueCap = parsed
		}
	}

	// 2. Initialize Subsystems
	approvalStore := lifecycle.NewMemoryApprovalStore()
	fourEyes := fourofeyes.NewEngine()
	dwellEngine := dwell.NewEngine()
	signerRegistry := signer.NewRegistry()

	// Register Pluggable Signers
	internalSigner, err := signer.NewInternalSigner(signer.InternalSignerConfig{
		ApproverID: "default-internal-approver",
	})
	if err != nil {
		log.Fatalf("[APPROVAL] Failed to initialize internal signer: %v", err)
	}
	signerRegistry.Register(internalSigner)

	tokenSigner, err := signer.NewCAVNTokenSigner(signer.CAVNTokenConfig{
		ApproverName: "Nguyen Van Dac",
	})
	if err != nil {
		log.Fatalf("[APPROVAL] Failed to initialize token signer: %v", err)
	}
	signerRegistry.Register(tokenSigner)

	remoteSigner, err := signer.NewCAVNRemoteSigner(signer.CAVNRemoteConfig{
		AuthMode: signer.RemoteAuthAutoApprove,
	})
	if err != nil {
		log.Fatalf("[APPROVAL] Failed to initialize remote signer: %v", err)
	}
	signerRegistry.Register(remoteSigner)

	// 3. Approval State Machine
	sm := lifecycle.NewApprovalStateMachine(approvalStore, fourEyes, dwellEngine, signerRegistry)

	// 4. Ledger In-Memory Queue
	ledgerQueue := ledger.NewBoundedQueue(queueCap, nil)
	log.Printf("[APPROVAL] Ledger micro-batch bounded queue initialized (capacity: %d)", queueCap)

	// 5. Service & Router
	service := api.NewService(sm, nil, ledgerQueue)
	router := api.NewRouter(service, ui.AssetHandler())

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 6. Start HTTP Server in background
	go func() {
		log.Printf("[APPROVAL] Server listening on port %s (http://localhost:%s)", port, port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[APPROVAL] Server error: %v", err)
		}
	}()

	// 7. Graceful Shutdown Signal Trapping
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[APPROVAL] Received signal %v, initiating graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[APPROVAL] HTTP shutdown error: %v", err)
	}

	if err := ledgerQueue.Close(); err != nil {
		log.Printf("[APPROVAL] Ledger queue close error: %v", err)
	}

	log.Println("[APPROVAL] Approval service stopped cleanly.")
}
