package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ei-evidence-platform/services/ledger"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	Port              string
	ImmudbAddress     string
	ImmudbPort        int
	ImmudbDatabase    string
	ImmudbUsername    string
	ImmudbPassword    string
	QueueCapacity     int
	BatchSize         int
	FlushIntervalMs   int
	WALDir            string
	TSAURL            string
	AnchorIntervalSec int
	ConnectTimeoutSec int
}

func loadConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}
	immuAddr := os.Getenv("IMMUDB_ADDRESS")
	if immuAddr == "" {
		immuAddr = "immudb"
	}
	immuPort := 3324
	if p := os.Getenv("IMMUDB_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			immuPort = parsed
		}
	}
	immuDB := os.Getenv("IMMUDB_DATABASE")
	if immuDB == "" {
		immuDB = "defaultdb"
	}
	immuUser := os.Getenv("IMMUDB_USERNAME")
	if immuUser == "" {
		immuUser = "immudb"
	}
	immuPass := os.Getenv("IMMUDB_PASSWORD")
	if immuPass == "" {
		immuPass = "immudb"
	}
	qCap := 50000
	if c := os.Getenv("LEDGER_QUEUE_CAPACITY"); c != "" {
		if parsed, err := strconv.Atoi(c); err == nil && parsed > 0 {
			qCap = parsed
		}
	}
	bSize := 100
	if b := os.Getenv("LEDGER_BATCH_SIZE"); b != "" {
		if parsed, err := strconv.Atoi(b); err == nil && parsed > 0 {
			bSize = parsed
		}
	}
	flushMs := 50
	if f := os.Getenv("LEDGER_FLUSH_INTERVAL_MS"); f != "" {
		if parsed, err := strconv.Atoi(f); err == nil && parsed > 0 {
			flushMs = parsed
		}
	}
	walDir := os.Getenv("WAL_DIR")
	if walDir == "" {
		walDir = "/var/lib/ledger/wal"
	}
	tsaURL := os.Getenv("RFC3161_TSA_URL")
	if tsaURL == "" {
		tsaURL = os.Getenv("TSA_URL")
	}
	anchorSec := 3600
	if a := os.Getenv("ANCHOR_INTERVAL_SEC"); a != "" {
		if parsed, err := strconv.Atoi(a); err == nil {
			anchorSec = parsed
		}
	}
	connectTimeoutSec := 30
	if ct := os.Getenv("IMMUDB_CONNECT_TIMEOUT_SEC"); ct != "" {
		if parsed, err := strconv.Atoi(ct); err == nil && parsed > 0 {
			connectTimeoutSec = parsed
		}
	}

	return Config{
		Port:              port,
		ImmudbAddress:     immuAddr,
		ImmudbPort:        immuPort,
		ImmudbDatabase:    immuDB,
		ImmudbUsername:    immuUser,
		ImmudbPassword:    immuPass,
		QueueCapacity:     qCap,
		BatchSize:         bSize,
		FlushIntervalMs:   flushMs,
		WALDir:            walDir,
		TSAURL:            tsaURL,
		AnchorIntervalSec: anchorSec,
		ConnectTimeoutSec: connectTimeoutSec,
	}
}

func generateEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evt-%s-%s", time.Now().UTC().Format("20060102150405"), hex.EncodeToString(b[:6]))
}

func main() {
	cfg := loadConfig()
	log.Printf("[LEDGER-WORKER] Starting on port %s (immudb target: %s:%d, database: %s)...",
		cfg.Port, cfg.ImmudbAddress, cfg.ImmudbPort, cfg.ImmudbDatabase)

	// 1. Initialize immudb REST client
	immuClient := ledger.NewRealImmudbClient(ledger.ImmudbConfig{
		Address:     cfg.ImmudbAddress,
		Port:        cfg.ImmudbPort,
		Database:    cfg.ImmudbDatabase,
		Username:    cfg.ImmudbUsername,
		Password:    cfg.ImmudbPassword,
		DialTimeout: 5 * time.Second,
	})

	// Retry connection to immudb with backoff to tolerate container boot sequence
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ConnectTimeoutSec)*time.Second)
	defer cancel()
	connected := false
	for {
		if err := immuClient.Open(ctx); err == nil {
			log.Printf("[LEDGER-WORKER] Successfully connected and authenticated to immudb at %s:%d", cfg.ImmudbAddress, cfg.ImmudbPort)
			connected = true
			break
		} else {
			log.Printf("[LEDGER-WORKER] Waiting for immudb to become ready (%v)... retrying in 2s", err)
			select {
			case <-ctx.Done():
				if os.Getenv("ALLOW_OFFLINE_BOOT") == "true" {
					log.Printf("[LEDGER-WORKER] Warning: Continuing boot in degraded offline mode: %v", ctx.Err())
					break
				}
				log.Fatalf("[LEDGER-WORKER] Timed out waiting for immudb connectivity: %v", ctx.Err())
			case <-time.After(2 * time.Second):
			}
			if ctx.Err() != nil && os.Getenv("ALLOW_OFFLINE_BOOT") == "true" {
				break
			}
		}
	}
	_ = connected

	// 2. Initialize WAL Manager
	var wal ledger.WALManager
	if cfg.WALDir != "" {
		if err := os.MkdirAll(cfg.WALDir, 0755); err != nil {
			log.Printf("[LEDGER-WORKER] Warning: Could not create WAL directory %s: %v", cfg.WALDir, err)
		}
		var err error
		wal, err = ledger.NewDiskWAL(cfg.WALDir, 10*1024*1024)
		if err != nil {
			log.Printf("[LEDGER-WORKER] Warning: Failed to initialize DiskWAL at %s: %v (falling back to memory-only)", cfg.WALDir, err)
		} else {
			log.Printf("[LEDGER-WORKER] DiskWAL initialized at %s (active segments: %d)", cfg.WALDir, wal.ActiveSegmentFiles())
		}
	}

	// 3. Initialize Merkle Tree & Bounded Queue
	tree := ledger.NewMemoryMerkleTree()
	queue := ledger.NewBoundedQueue(cfg.QueueCapacity, wal)

	// 4. Initialize & Start MicroBatchWorker
	workerCfg := ledger.WorkerConfig{
		BatchSize:         cfg.BatchSize,
		FlushInterval:     time.Duration(cfg.FlushIntervalMs) * time.Millisecond,
		WALReplayInterval: 1 * time.Second,
	}
	worker := ledger.NewMicroBatchWorker(workerCfg, queue, immuClient, tree, wal)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	worker.Start(workerCtx)
	log.Println("[LEDGER-WORKER] MicroBatchWorker background flusher started.")

	// 5. Initialize Anchor Service (optional)
	var anchorService ledger.AnchorService
	if cfg.TSAURL != "" {
		tsaClient := ledger.NewRFC3161Client(ledger.TSAClientConfig{
			PrimaryURL:  cfg.TSAURL,
			HTTPTimeout: 10 * time.Second,
		})
		anchorService = ledger.NewAnchorService(immuClient, tsaClient, tree)
		if cfg.AnchorIntervalSec > 0 {
			anchorService.StartPeriodicAnchoring(workerCtx, time.Duration(cfg.AnchorIntervalSec)*time.Second)
			log.Printf("[LEDGER-WORKER] Periodic RFC 3161 TSA anchoring started (interval: %ds)", cfg.AnchorIntervalSec)
		}
	}

	// 6. Assemble HTTP Router
	mux := http.NewServeMux()

	// Probes
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		h := worker.Health(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if h.Status == "DOWN" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(h)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		h := worker.Health(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h)
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		h := worker.Health(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if h.ImmudbStatus == "CONNECTED" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "READY"})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "NOT_READY"})
		}
	})

	// Ingestion & Event Lookup endpoint
	mux.HandleFunc("/api/v1/ledger/events", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var ev ledger.AuditEventEnvelope
			if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
				http.Error(w, "Invalid JSON envelope: "+err.Error(), http.StatusBadRequest)
				return
			}
			if ev.EventID == "" {
				ev.EventID = generateEventID()
			}
			if ev.Timestamp.IsZero() {
				ev.Timestamp = time.Now().UTC()
			}
			if err := queue.Enqueue(&ev); err != nil {
				if errors.Is(err, ledger.ErrQueueFull) {
					http.Error(w, "Queue saturated", http.StatusServiceUnavailable)
				} else {
					http.Error(w, "Enqueue failed: "+err.Error(), http.StatusInternalServerError)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":   "ENQUEUED",
				"event_id": ev.EventID,
			})

		case http.MethodGet:
			// Query by id or correlation_id
			if eventID := r.URL.Query().Get("event_id"); eventID != "" {
				ev, err := immuClient.GetEvent(r.Context(), eventID)
				if err != nil {
					http.Error(w, "Event not found: "+err.Error(), http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ev)
				return
			}
			if corrID := r.URL.Query().Get("correlation_id"); corrID != "" {
				events, err := immuClient.GetEventsByCorrelation(r.Context(), corrID)
				if err != nil {
					http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(events)
				return
			}
			http.Error(w, "Query parameter 'event_id' or 'correlation_id' required", http.StatusBadRequest)

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	// Subpath handler for /api/v1/ledger/events/
	mux.HandleFunc("/api/v1/ledger/events/", func(w http.ResponseWriter, r *http.Request) {
		subpath := strings.TrimPrefix(r.URL.Path, "/api/v1/ledger/events/")
		if subpath == "" {
			http.NotFound(w, r)
			return
		}

		if strings.HasPrefix(subpath, "correlation/") {
			corrID := strings.TrimPrefix(subpath, "correlation/")
			events, err := immuClient.GetEventsByCorrelation(r.Context(), corrID)
			if err != nil {
				http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(events)
			return
		}

		// Direct event ID lookup
		ev, err := immuClient.GetEvent(r.Context(), subpath)
		if err != nil {
			http.Error(w, "Event not found: "+err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ev)
	})

	// Stats endpoint
	mux.HandleFunc("/api/v1/ledger/stats", func(w http.ResponseWriter, r *http.Request) {
		events, batches, replayed := worker.Stats()
		qStats := queue.Stats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"worker": map[string]interface{}{
				"events_ingested": events,
				"batches_flushed": batches,
				"wal_replayed":    replayed,
			},
			"queue": qStats,
		})
	})

	// Anchoring endpoints (if configured)
	if anchorService != nil {
		anchorHandler := ledger.NewAnchorHTTPHandler(anchorService, worker)
		mux.Handle("/api/v1/ledger/anchors/", anchorHandler)
	}

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[LEDGER-WORKER] Server listening on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[LEDGER-WORKER] Server error: %v", err)
		}
	}()

	// 7. Trapping termination signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[LEDGER-WORKER] Received signal %v, initiating graceful shutdown...", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	_ = srv.Shutdown(shutdownCtx)
	if anchorService != nil {
		anchorService.Stop()
	}
	workerCancel()
	worker.Stop()
	_ = queue.Close()
	if wal != nil {
		_ = wal.Close()
	}
	_ = immuClient.Close(context.Background())
	log.Println("[LEDGER-WORKER] Shutdown complete.")
}
