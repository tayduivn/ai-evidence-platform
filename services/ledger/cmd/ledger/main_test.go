package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ei-evidence-platform/services/ledger"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Ensure clean environment
	os.Unsetenv("PORT")
	os.Unsetenv("IMMUDB_ADDRESS")
	os.Unsetenv("IMMUDB_PORT")
	os.Unsetenv("LEDGER_QUEUE_CAPACITY")
	os.Unsetenv("LEDGER_BATCH_SIZE")
	os.Unsetenv("LEDGER_FLUSH_INTERVAL_MS")
	os.Unsetenv("WAL_DIR")

	cfg := loadConfig()
	if cfg.Port != "8083" {
		t.Errorf("expected default Port 8083, got %s", cfg.Port)
	}
	if cfg.ImmudbAddress != "immudb" {
		t.Errorf("expected default ImmudbAddress immudb, got %s", cfg.ImmudbAddress)
	}
	if cfg.ImmudbPort != 3324 {
		t.Errorf("expected default ImmudbPort 3324, got %d", cfg.ImmudbPort)
	}
	if cfg.QueueCapacity != 50000 {
		t.Errorf("expected default QueueCapacity 50000, got %d", cfg.QueueCapacity)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("expected default BatchSize 100, got %d", cfg.BatchSize)
	}
	if cfg.FlushIntervalMs != 50 {
		t.Errorf("expected default FlushIntervalMs 50, got %d", cfg.FlushIntervalMs)
	}
	if cfg.WALDir != "/var/lib/ledger/wal" {
		t.Errorf("expected default WALDir /var/lib/ledger/wal, got %s", cfg.WALDir)
	}
	if cfg.AnchorIntervalSec != 3600 {
		t.Errorf("expected default AnchorIntervalSec 3600, got %d", cfg.AnchorIntervalSec)
	}
}

func TestLoadConfig_CustomEnv(t *testing.T) {
	os.Setenv("PORT", "9099")
	os.Setenv("IMMUDB_ADDRESS", "10.0.0.5")
	os.Setenv("IMMUDB_PORT", "3325")
	os.Setenv("LEDGER_QUEUE_CAPACITY", "1000")
	os.Setenv("LEDGER_BATCH_SIZE", "20")
	os.Setenv("LEDGER_FLUSH_INTERVAL_MS", "25")
	os.Setenv("WAL_DIR", "/tmp/wal")
	os.Setenv("RFC3161_TSA_URL", "http://tsa.example.com")
	os.Setenv("ANCHOR_INTERVAL_SEC", "1800")
	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("IMMUDB_ADDRESS")
		os.Unsetenv("IMMUDB_PORT")
		os.Unsetenv("LEDGER_QUEUE_CAPACITY")
		os.Unsetenv("LEDGER_BATCH_SIZE")
		os.Unsetenv("LEDGER_FLUSH_INTERVAL_MS")
		os.Unsetenv("WAL_DIR")
		os.Unsetenv("RFC3161_TSA_URL")
		os.Unsetenv("ANCHOR_INTERVAL_SEC")
	}()

	cfg := loadConfig()
	if cfg.Port != "9099" {
		t.Errorf("expected Port 9099, got %s", cfg.Port)
	}
	if cfg.ImmudbAddress != "10.0.0.5" {
		t.Errorf("expected ImmudbAddress 10.0.0.5, got %s", cfg.ImmudbAddress)
	}
	if cfg.ImmudbPort != 3325 {
		t.Errorf("expected ImmudbPort 3325, got %d", cfg.ImmudbPort)
	}
	if cfg.QueueCapacity != 1000 {
		t.Errorf("expected QueueCapacity 1000, got %d", cfg.QueueCapacity)
	}
	if cfg.BatchSize != 20 {
		t.Errorf("expected BatchSize 20, got %d", cfg.BatchSize)
	}
	if cfg.FlushIntervalMs != 25 {
		t.Errorf("expected FlushIntervalMs 25, got %d", cfg.FlushIntervalMs)
	}
	if cfg.WALDir != "/tmp/wal" {
		t.Errorf("expected WALDir /tmp/wal, got %s", cfg.WALDir)
	}
	if cfg.TSAURL != "http://tsa.example.com" {
		t.Errorf("expected TSAURL http://tsa.example.com, got %s", cfg.TSAURL)
	}
	if cfg.AnchorIntervalSec != 1800 {
		t.Errorf("expected AnchorIntervalSec 1800, got %d", cfg.AnchorIntervalSec)
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()
	if id1 == "" || id2 == "" {
		t.Fatalf("expected non-empty event ID")
	}
	if id1 == id2 {
		t.Fatalf("expected unique event IDs, got %s and %s", id1, id2)
	}
	if len(id1) < 20 {
		t.Fatalf("expected formatted event ID prefix, got %s", id1)
	}
}

func TestHTTPHandlers(t *testing.T) {
	mockClient := ledger.NewMockImmudbClient()
	tree := ledger.NewMemoryMerkleTree()
	queue := ledger.NewBoundedQueue(100, nil)
	workerCfg := ledger.WorkerConfig{
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
	}
	worker := ledger.NewMicroBatchWorker(workerCfg, queue, mockClient, tree, nil)
	workerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker.Start(workerCtx)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		h := worker.Health(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
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
	mux.HandleFunc("/api/v1/ledger/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var ev ledger.AuditEventEnvelope
			if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if ev.EventID == "" {
				ev.EventID = generateEventID()
			}
			_ = queue.Enqueue(&ev)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ENQUEUED", "event_id": ev.EventID})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/v1/ledger/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "OK"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test /health
	resp, err := http.Get(server.URL + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /health, got %v (%v)", resp.StatusCode, err)
	}

	// Test /ready
	resp, err = http.Get(server.URL + "/ready")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /ready, got %v (%v)", resp.StatusCode, err)
	}

	// Test POST /api/v1/ledger/events
	payload := `{"ai_system_id":"test-sys","event_type":"LLM_INFERENCE"}`
	resp, err = http.Post(server.URL+"/api/v1/ledger/events", "application/json", bytes.NewBufferString(payload))
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 from POST events, got %v (%v)", resp.StatusCode, err)
	}
	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["status"] != "ENQUEUED" || res["event_id"] == "" {
		t.Fatalf("unexpected response payload: %v", res)
	}

	// Test /api/v1/ledger/stats
	resp, err = http.Get(server.URL + "/api/v1/ledger/stats")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/ledger/stats, got %v (%v)", resp.StatusCode, err)
	}
}
