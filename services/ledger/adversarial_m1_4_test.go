package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// CHALLENGE SUITE 1: ADVANCED DISK WAL MULTI-CRASH RECOVERY REPLAY
// ============================================================================

// TestAdversarial_DiskWAL_MultiCrashRecoveryReplay stresses cascading crashes:
// Crash 1 (15 events) -> Crash 2 (20 events) -> Crash 3 (25 events) -> Restart & Replay all 60 events.
func TestAdversarial_DiskWAL_MultiCrashRecoveryReplay(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_wal_multicrash_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	expectedEvents := make([]string, 0, 60)

	// Episode 1: write 15 events, crash abruptly (close FD without Rotate)
	wal1, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Episode 1 NewDiskWAL failed: %v", err)
	}
	for i := 0; i < 15; i++ {
		evID := fmt.Sprintf("crash-ep1-%03d", i)
		expectedEvents = append(expectedEvents, evID)
		if err := wal1.WriteEvent(&AuditEventEnvelope{EventID: evID, Timestamp: time.Now().UTC()}); err != nil {
			t.Fatalf("Episode 1 WriteEvent failed: %v", err)
		}
	}
	_ = wal1.Close()

	// Episode 2: restart, write 20 events, crash abruptly
	wal2, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Episode 2 NewDiskWAL failed: %v", err)
	}
	for i := 0; i < 20; i++ {
		evID := fmt.Sprintf("crash-ep2-%03d", i)
		expectedEvents = append(expectedEvents, evID)
		if err := wal2.WriteEvent(&AuditEventEnvelope{EventID: evID, Timestamp: time.Now().UTC()}); err != nil {
			t.Fatalf("Episode 2 WriteEvent failed: %v", err)
		}
	}
	_ = wal2.Close()

	// Episode 3: restart, write 25 events, crash abruptly
	wal3, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Episode 3 NewDiskWAL failed: %v", err)
	}
	for i := 0; i < 25; i++ {
		evID := fmt.Sprintf("crash-ep3-%03d", i)
		expectedEvents = append(expectedEvents, evID)
		if err := wal3.WriteEvent(&AuditEventEnvelope{EventID: evID, Timestamp: time.Now().UTC()}); err != nil {
			t.Fatalf("Episode 3 WriteEvent failed: %v", err)
		}
	}
	_ = wal3.Close()

	// Final Recovery: start wal4, replay all pending historical uncommitted segments
	wal4, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Recovery NewDiskWAL failed: %v", err)
	}
	defer wal4.Close()

	var replayedIDs []string
	replayedCount, err := wal4.ReplayPending(func(batch []*AuditEventEnvelope) error {
		for _, ev := range batch {
			replayedIDs = append(replayedIDs, ev.EventID)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("ReplayPending returned unexpected error: %v", err)
	}

	if replayedCount != len(expectedEvents) {
		t.Fatalf("Expected %d total replayed events across 3 crashes, got %d", len(expectedEvents), replayedCount)
	}

	for i, expectedID := range expectedEvents {
		if replayedIDs[i] != expectedID {
			t.Errorf("Mismatch at replayed event [%d]: expected %s, got %s", i, expectedID, replayedIDs[i])
		}
	}
}

// TestAdversarial_DiskWAL_EmptyFileHandling verifies that an empty pre-existing WAL file (0 bytes)
// does not cause unnecessary sequence increments or replay errors.
func TestAdversarial_DiskWAL_EmptyFileHandling(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv_wal_empty_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create an empty segment wal-00000000.log
	emptySeg := filepath.Join(tempDir, "wal-00000000.log")
	f, err := os.Create(emptySeg)
	if err != nil {
		t.Fatalf("Failed to create empty segment: %v", err)
	}
	f.Close()

	wal, err := NewDiskWAL(tempDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewDiskWAL failed on empty segment: %v", err)
	}
	defer wal.Close()

	// Active sequence should remain 0 because 00000000.log was 0 bytes
	ev := &AuditEventEnvelope{EventID: "ev-after-empty", Timestamp: time.Now().UTC()}
	if err := wal.WriteEvent(ev); err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}

	// ReplayPending on an active-only wal should return 0
	replayed, err := wal.ReplayPending(func(batch []*AuditEventEnvelope) error {
		return nil
	})
	if err != nil {
		t.Fatalf("ReplayPending failed: %v", err)
	}
	if replayed != 0 {
		t.Errorf("Expected 0 replayed events for current active-only segment, got %d", replayed)
	}
}

// ============================================================================
// CHALLENGE SUITE 2: QUEUE CONCURRENCY DURING WORKER SHUTDOWN
// ============================================================================

// TestAdversarial_QueueConcurrency_WorkerShutdownStress runs 50 producers pushing
// events at maximum speed while a MicroBatchWorker is actively running, then stops
// both the worker and closes the queue concurrently. Asserts zero panics and clean termination.
func TestAdversarial_QueueConcurrency_WorkerShutdownStress(t *testing.T) {
	for round := 0; round < 5; round++ {
		queue := NewBoundedQueue(200, nil)
		mockClient := NewMockImmudbClient()
		ctx := context.Background()
		_ = mockClient.Open(ctx)

		cfg := WorkerConfig{
			BatchSize:     20,
			FlushInterval: 10 * time.Millisecond,
		}
		worker := NewMicroBatchWorker(cfg, queue, mockClient, nil, nil)
		worker.Start(ctx)

		const numProducers = 50
		const eventsPerProducer = 100
		var wg sync.WaitGroup
		var closedErrors atomic.Uint64
		var successfulPushes atomic.Uint64

		startSig := make(chan struct{})

		for p := 0; p < numProducers; p++ {
			wg.Add(1)
			go func(producerID int) {
				defer wg.Done()
				<-startSig

				for i := 0; i < eventsPerProducer; i++ {
					ev := &AuditEventEnvelope{
						EventID:       fmt.Sprintf("shut-p%d-ev%d", producerID, i),
						CorrelationID: fmt.Sprintf("corr-p%d", producerID),
						Timestamp:     time.Now().UTC(),
					}
					err := queue.Enqueue(ev)
					if err == nil {
						successfulPushes.Add(1)
					} else if errors.Is(err, ErrQueueClosed) {
						closedErrors.Add(1)
					}
				}
			}(p)
		}

		// Fire producers
		close(startSig)

		// Let them run for a small jitter then trigger concurrent worker stop and queue close
		time.Sleep(5 * time.Millisecond)

		var shutdownWg sync.WaitGroup
		shutdownWg.Add(2)

		go func() {
			defer shutdownWg.Done()
			worker.Stop()
		}()

		go func() {
			defer shutdownWg.Done()
			_ = queue.Close()
		}()

		shutdownWg.Wait()
		wg.Wait()

		stats := queue.Stats()
		totalCalls := uint64(numProducers * eventsPerProducer)
		handled := stats.EnqueuedTotal + stats.DroppedTotal + closedErrors.Load()
		if handled != totalCalls {
			t.Logf("Round %d: Enqueued=%d, Dropped=%d, ClosedErrors=%d (Sum=%d, TotalCalls=%d)",
				round, stats.EnqueuedTotal, stats.DroppedTotal, closedErrors.Load(), handled, totalCalls)
		}

		_ = mockClient.Close(ctx)
	}
}

// ============================================================================
// CHALLENGE SUITE 3: IMMUDB CLIENT ERROR HANDLING (401, 500, 404, NETWORK FAULTS)
// ============================================================================

// TestAdversarial_RealImmudbClient_AllHTTPStatusErrors tests all RealImmudbClient methods
// when receiving 401 Unauthorized, 500 Internal Server Error, and 404 Not Found.
func TestAdversarial_RealImmudbClient_AllHTTPStatusErrors(t *testing.T) {
	t.Run("Status401_Unauthorized_AcrossAllMethods", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/login" {
				// Allow login so client gets connected, but subsequent calls return 401
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "expired-token"})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("session expired or token unauthorized"))
		}))
		defer server.Close()

		u, _ := url.Parse(server.URL)
		port, _ := strconv.Atoi(u.Port())
		client := NewRealImmudbClient(ImmudbConfig{
			Address: u.Hostname(),
			Port:    port,
		})

		ctx := context.Background()
		if err := client.Open(ctx); err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer client.Close(ctx)

		// 1. HealthCheck
		if err := client.HealthCheck(ctx); err == nil {
			t.Errorf("Expected HealthCheck to fail on 401")
		}

		// 2. CommitBatch
		batch := []*AuditEventEnvelope{{EventID: "ev-401", Timestamp: time.Now().UTC()}}
		if _, err := client.CommitBatch(ctx, batch); err == nil {
			t.Errorf("Expected CommitBatch to fail on 401")
		}

		// 3. GetEvent
		if _, err := client.GetEvent(ctx, "ev-401"); err == nil {
			t.Errorf("Expected GetEvent to fail on 401")
		}

		// 4. GetEventsByCorrelation
		if _, err := client.GetEventsByCorrelation(ctx, "corr-401"); err == nil {
			t.Errorf("Expected GetEventsByCorrelation to fail on 401")
		}

		// 5. SaveAnchor
		anchor := &AnchorRecord{AnchorID: "anc-401", CreatedAt: time.Now().UTC()}
		if err := client.SaveAnchor(ctx, anchor); err == nil {
			t.Errorf("Expected SaveAnchor to fail on 401")
		}

		// 6. GetLatestAnchor
		if _, err := client.GetLatestAnchor(ctx); err == nil {
			t.Errorf("Expected GetLatestAnchor to fail on 401")
		}

		// 7. GetAnchorByID
		if _, err := client.GetAnchorByID(ctx, "anc-401"); err == nil {
			t.Errorf("Expected GetAnchorByID to fail on 401")
		}
	})

	t.Run("Status500_InternalServerError_AcrossAllMethods", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/login" {
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "valid-token"})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("fatal storage engine deadlock"))
		}))
		defer server.Close()

		u, _ := url.Parse(server.URL)
		port, _ := strconv.Atoi(u.Port())
		client := NewRealImmudbClient(ImmudbConfig{
			Address: u.Hostname(),
			Port:    port,
		})

		ctx := context.Background()
		if err := client.Open(ctx); err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer client.Close(ctx)

		// 1. HealthCheck
		if err := client.HealthCheck(ctx); err == nil {
			t.Errorf("Expected HealthCheck to fail on 500")
		}

		// 2. CommitBatch
		batch := []*AuditEventEnvelope{{EventID: "ev-500", Timestamp: time.Now().UTC()}}
		if _, err := client.CommitBatch(ctx, batch); err == nil {
			t.Errorf("Expected CommitBatch to fail on 500")
		}

		// 3. GetLatestState
		if _, _, err := client.GetLatestState(ctx); err == nil {
			t.Errorf("Expected GetLatestState to fail on 500")
		}

		// 4. GetEvent
		if _, err := client.GetEvent(ctx, "ev-500"); err == nil {
			t.Errorf("Expected GetEvent to fail on 500")
		}

		// 5. GetEventsByCorrelation
		if _, err := client.GetEventsByCorrelation(ctx, "corr-500"); err == nil {
			t.Errorf("Expected GetEventsByCorrelation to fail on 500")
		}

		// 6. SaveAnchor
		anchor := &AnchorRecord{AnchorID: "anc-500", CreatedAt: time.Now().UTC()}
		if err := client.SaveAnchor(ctx, anchor); err == nil {
			t.Errorf("Expected SaveAnchor to fail on 500")
		}

		// 7. GetLatestAnchor
		if _, err := client.GetLatestAnchor(ctx); err == nil {
			t.Errorf("Expected GetLatestAnchor to fail on 500")
		}

		// 8. GetAnchorByID
		if _, err := client.GetAnchorByID(ctx, "anc-500"); err == nil {
			t.Errorf("Expected GetAnchorByID to fail on 500")
		}
	})

	t.Run("Status404_NotFound_EdgeCases", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/login" {
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "valid-token"})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("resource does not exist"))
		}))
		defer server.Close()

		u, _ := url.Parse(server.URL)
		port, _ := strconv.Atoi(u.Port())
		client := NewRealImmudbClient(ImmudbConfig{
			Address: u.Hostname(),
			Port:    port,
		})

		ctx := context.Background()
		if err := client.Open(ctx); err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer client.Close(ctx)

		// GetEvent 404
		_, err := client.GetEvent(ctx, "missing-event-uuid")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error for missing event, got %v", err)
		}

		// GetAnchorByID 404
		_, err = client.GetAnchorByID(ctx, "missing-anchor-uuid")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error for missing anchor, got %v", err)
		}

		// GetLatestAnchor 404
		_, err = client.GetLatestAnchor(ctx)
		if err == nil || !strings.Contains(err.Error(), "no anchors found") {
			t.Errorf("Expected 'no anchors found' error, got %v", err)
		}
	})

	t.Run("ClientNotConnected_GuardRails", func(t *testing.T) {
		client := NewRealImmudbClient(ImmudbConfig{})
		ctx := context.Background()

		// Without Open(), all operations should return clean errors rather than panic
		if err := client.HealthCheck(ctx); err == nil {
			t.Errorf("Expected error for unconnected HealthCheck")
		}
		if _, err := client.CommitBatch(ctx, []*AuditEventEnvelope{{EventID: "1"}}); err == nil {
			t.Errorf("Expected error for unconnected CommitBatch")
		}
		if _, _, err := client.GetLatestState(ctx); err == nil {
			t.Errorf("Expected error for unconnected GetLatestState")
		}
		if _, err := client.GetEvent(ctx, "1"); err == nil {
			t.Errorf("Expected error for unconnected GetEvent")
		}
		if _, err := client.GetEventsByCorrelation(ctx, "1"); err == nil {
			t.Errorf("Expected error for unconnected GetEventsByCorrelation")
		}
		if err := client.SaveAnchor(ctx, &AnchorRecord{AnchorID: "1"}); err == nil {
			t.Errorf("Expected error for unconnected SaveAnchor")
		}
		if _, err := client.GetLatestAnchor(ctx); err == nil {
			t.Errorf("Expected error for unconnected GetLatestAnchor")
		}
		if _, err := client.GetAnchorByID(ctx, "1"); err == nil {
			t.Errorf("Expected error for unconnected GetAnchorByID")
		}
	})

	t.Run("MalformedJSON_AndCorruptBase64_Responses", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/login" {
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "valid-token"})
				return
			}
			w.WriteHeader(http.StatusOK)
			// Return corrupt base64 in value
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "this-is-not-valid-base64!@@#$%"})
		}))
		defer server.Close()

		u, _ := url.Parse(server.URL)
		port, _ := strconv.Atoi(u.Port())
		client := NewRealImmudbClient(ImmudbConfig{
			Address: u.Hostname(),
			Port:    port,
		})

		ctx := context.Background()
		_ = client.Open(ctx)
		defer client.Close(ctx)

		if _, err := client.GetEvent(ctx, "test"); err == nil {
			t.Errorf("Expected error on corrupt base64 from server")
		}
		if _, err := client.GetLatestAnchor(ctx); err == nil {
			t.Errorf("Expected error on corrupt base64 from server")
		}
	})
}

// ============================================================================
// CHALLENGE SUITE 4: ADVANCED RFC 3161 MOCK TSA ERROR INJECTION
// ============================================================================

// TestAdversarial_MockTSA_DeepErrorInjection tests deep TSA failure modes:
// malformed ASN.1 response, nonce mismatch, hash mismatch, and HTTP network drops.
func TestAdversarial_MockTSA_DeepErrorInjection(t *testing.T) {
	t.Run("MalformedASN1_Response", func(t *testing.T) {
		// Server returns 200 OK with random garbage bytes instead of DER ASN.1
		garbageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04})
		}))
		defer garbageServer.Close()

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL: garbageServer.URL,
			MaxRetries: 1,
		})

		_, _, _, err := client.RequestTimestamp(context.Background(), []byte("sample-hash"))
		if err == nil {
			t.Fatalf("Expected error when TSA returns malformed ASN.1 bytes, got nil")
		}
		t.Logf("Correctly rejected malformed ASN.1 response: %v", err)
	})

	t.Run("NonceTampering_Detected", func(t *testing.T) {
		tsa, err := NewMockTSAServer()
		if err != nil {
			t.Fatalf("NewMockTSAServer failed: %v", err)
		}
		defer tsa.Close()

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL: tsa.URL(),
			MaxRetries: 1,
		})

		rootHash := []byte("root-hash-nonce-test")
		// Directly call RequestTimestamp to get valid DER
		rawResp, _, _, err := client.RequestTimestamp(context.Background(), rootHash)
		if err != nil {
			t.Fatalf("RequestTimestamp failed: %v", err)
		}

		// Now validate with a DIFFERENT nonce
		differentNonce := big.NewInt(123456789)
		_, _, err = client.ValidateResponse(rawResp, rootHash, differentNonce)
		if err == nil {
			t.Fatalf("Expected ValidateResponse to fail on nonce mismatch, but it succeeded!")
		}
		if !strings.Contains(err.Error(), "nonce mismatch") {
			t.Errorf("Expected 'nonce mismatch' error, got %v", err)
		}
	})

	t.Run("RootHashTampering_Detected", func(t *testing.T) {
		tsa, err := NewMockTSAServer()
		if err != nil {
			t.Fatalf("NewMockTSAServer failed: %v", err)
		}
		defer tsa.Close()

		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL: tsa.URL(),
			MaxRetries: 1,
		})

		rootHash := []byte("authentic-root-hash-32-bytes!!")
		tamperedRootHash := []byte("tampered--root-hash-32-bytes!!")

		rawResp, tstInfo, _, err := client.RequestTimestamp(context.Background(), rootHash)
		if err != nil {
			t.Fatalf("RequestTimestamp failed: %v", err)
		}

		// Validate with tampered root hash
		_, _, err = client.ValidateResponse(rawResp, tamperedRootHash, tstInfo.Nonce)
		if err == nil {
			t.Fatalf("Expected ValidateResponse to fail on root hash mismatch, but it succeeded!")
		}
		if !strings.Contains(err.Error(), "hashed message in TSTInfo does not match") {
			t.Errorf("Expected root hash mismatch error, got %v", err)
		}
	})

	t.Run("NetworkConnectionDropped", func(t *testing.T) {
		// Point to an unavailable address to test fast timeout
		client := NewRFC3161Client(TSAClientConfig{
			PrimaryURL:  "http://127.0.0.1:59999/unreachable-tsa",
			HTTPTimeout: 200 * time.Millisecond,
			MaxRetries:  1,
		})

		start := time.Now()
		_, _, _, err := client.RequestTimestamp(context.Background(), []byte("sample-hash"))
		duration := time.Since(start)

		if err == nil {
			t.Fatalf("Expected network error on unreachable TSA endpoint, got nil")
		}
		if duration > 3*time.Second {
			t.Errorf("Timeout handling took too long: %v", duration)
		}
	})
}
