package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMockImmudbClient_OpenAndClose(t *testing.T) {
	client := NewMockImmudbClient()
	ctx := context.Background()

	if err := client.Open(ctx); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	if err := client.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Test unhealthy state
	client.SetHealthy(false)
	if err := client.HealthCheck(ctx); err == nil {
		t.Errorf("Expected health check failure when unhealthy")
	}
	if err := client.Open(ctx); err == nil {
		t.Errorf("Expected open failure when unhealthy")
	}
}

func TestMockImmudbClient_CommitBatchAndStateRoot(t *testing.T) {
	client := NewMockImmudbClient()
	ctx := context.Background()

	initialTx, initialRoot, err := client.GetLatestState(ctx)
	if err != nil {
		t.Fatalf("GetLatestState failed: %v", err)
	}
	if initialTx != 0 {
		t.Errorf("Expected initial TxID=0, got %d", initialTx)
	}
	if len(initialRoot) != 32 {
		t.Errorf("Expected 32-byte initial root, got %d bytes", len(initialRoot))
	}

	events := []*AuditEventEnvelope{
		{
			EventID:       "ev-001",
			CorrelationID: "corr-100",
			AISystemID:    "credit-scorer",
			OutputPayload: "APPROVED",
			Timestamp:     time.Now().UTC(),
		},
		{
			EventID:       "ev-002",
			CorrelationID: "corr-100",
			AISystemID:    "credit-scorer",
			OutputPayload: "INTERCEPTED",
			Timestamp:     time.Now().UTC(),
		},
	}

	res, err := client.CommitBatch(ctx, events)
	if err != nil {
		t.Fatalf("CommitBatch failed: %v", err)
	}
	if res.TxID != 1 {
		t.Errorf("Expected TxID=1, got %d", res.TxID)
	}
	if res.EventCount != 2 {
		t.Errorf("Expected EventCount=2, got %d", res.EventCount)
	}

	newTx, newRoot, err := client.GetLatestState(ctx)
	if err != nil {
		t.Fatalf("GetLatestState failed: %v", err)
	}
	if newTx != 1 {
		t.Errorf("Expected new TxID=1, got %d", newTx)
	}
	if string(newRoot) == string(initialRoot) {
		t.Errorf("Root hash should have changed after commit")
	}

	if client.TotalEvents() != 2 {
		t.Errorf("Expected TotalEvents=2, got %d", client.TotalEvents())
	}
	if client.TotalTransactions() != 1 {
		t.Errorf("Expected TotalTransactions=1, got %d", client.TotalTransactions())
	}
}

func TestMockImmudbClient_GetEventAndCorrelation(t *testing.T) {
	client := NewMockImmudbClient()
	ctx := context.Background()

	events := []*AuditEventEnvelope{
		{
			EventID:       "ev-101",
			CorrelationID: "corr-200",
			AISystemID:    "loan-evaluator",
			OutputPayload: "SCORE_720",
			Timestamp:     time.Now().UTC(),
		},
		{
			EventID:       "ev-102",
			CorrelationID: "corr-200",
			AISystemID:    "loan-evaluator",
			OutputPayload: "SCORE_800",
			Timestamp:     time.Now().UTC(),
		},
		{
			EventID:       "ev-103",
			CorrelationID: "corr-300",
			AISystemID:    "loan-evaluator",
			OutputPayload: "REJECTED",
			Timestamp:     time.Now().UTC(),
		},
	}

	if _, err := client.CommitBatch(ctx, events); err != nil {
		t.Fatalf("CommitBatch failed: %v", err)
	}

	// Fetch single event
	ev, err := client.GetEvent(ctx, "ev-101")
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if ev.OutputPayload != "SCORE_720" {
		t.Errorf("Expected OutputPayload 'SCORE_720', got %s", ev.OutputPayload)
	}

	// Fetch non-existent
	if _, err := client.GetEvent(ctx, "non-existent"); err == nil {
		t.Errorf("Expected error for non-existent event")
	}

	// Fetch by correlation
	corrEvents, err := client.GetEventsByCorrelation(ctx, "corr-200")
	if err != nil {
		t.Fatalf("GetEventsByCorrelation failed: %v", err)
	}
	if len(corrEvents) != 2 {
		t.Errorf("Expected 2 events for corr-200, got %d", len(corrEvents))
	}
}

func TestMockImmudbClient_AnchorLifecycle(t *testing.T) {
	client := NewMockImmudbClient()
	ctx := context.Background()

	anchor := &AnchorRecord{
		AnchorID:          "anc-1-20261005",
		ImmudbTxID:        1,
		ImmudbRootHash:    "deadbeef",
		TSAURL:            "https://mock.tsa/tsr",
		TimestampTokenB64: "dGVzdC10b2tlbg==",
		VerifiedGenTime:   time.Now().UTC(),
		Status:            "VALID",
		CreatedAt:         time.Now().UTC(),
	}

	if err := client.SaveAnchor(ctx, anchor); err != nil {
		t.Fatalf("SaveAnchor failed: %v", err)
	}

	latest, err := client.GetLatestAnchor(ctx)
	if err != nil {
		t.Fatalf("GetLatestAnchor failed: %v", err)
	}
	if latest.AnchorID != "anc-1-20261005" {
		t.Errorf("Expected AnchorID 'anc-1-20261005', got %s", latest.AnchorID)
	}

	byID, err := client.GetAnchorByID(ctx, "anc-1-20261005")
	if err != nil {
		t.Fatalf("GetAnchorByID failed: %v", err)
	}
	if byID.ImmudbRootHash != "deadbeef" {
		t.Errorf("Expected root hash 'deadbeef', got %s", byID.ImmudbRootHash)
	}

	if _, err := client.GetAnchorByID(ctx, "invalid-id"); err == nil {
		t.Errorf("Expected error for non-existent anchor ID")
	}
}

func TestMockImmudbClient_SimulateTamper(t *testing.T) {
	client := NewMockImmudbClient()
	ctx := context.Background()

	ev := &AuditEventEnvelope{
		EventID:       "ev-tamper-01",
		CorrelationID: "tx-tamper",
		OutputPayload: "ORIGINAL_VALUE",
		PayloadHash:   "orig_hash",
		Timestamp:     time.Now().UTC(),
	}

	if _, err := client.CommitBatch(ctx, []*AuditEventEnvelope{ev}); err != nil {
		t.Fatalf("CommitBatch failed: %v", err)
	}

	if err := client.SimulateTamper("ev-tamper-01", "output_payload", "TAMPERED_VALUE"); err != nil {
		t.Fatalf("SimulateTamper failed: %v", err)
	}

	tampered, err := client.GetEvent(ctx, "ev-tamper-01")
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if tampered.OutputPayload != "TAMPERED_VALUE" {
		t.Errorf("Expected OutputPayload 'TAMPERED_VALUE', got %s", tampered.OutputPayload)
	}
}

func TestRealImmudbClient_Lifecycle(t *testing.T) {
	cfg := ImmudbConfig{
		Address:     "127.0.0.1",
		Port:        59999, // Unused port to test connection failure
		DialTimeout: 100 * time.Millisecond,
	}
	client := NewRealImmudbClient(cfg)
	ctx := context.Background()

	// Connect attempt on unused port should fail gracefully
	if err := client.Open(ctx); err == nil {
		t.Errorf("Expected connection failure on unused port")
	}

	if err := client.HealthCheck(ctx); err == nil {
		t.Errorf("Expected HealthCheck failure when disconnected")
	}

	if _, err := client.CommitBatch(ctx, nil); err == nil {
		t.Errorf("Expected CommitBatch error when disconnected")
	}

	if _, _, err := client.GetLatestState(ctx); err == nil {
		t.Errorf("Expected GetLatestState error when disconnected")
	}

	if err := client.Close(ctx); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestRealImmudbClient_EndToEndMockServer(t *testing.T) {
	var mu sync.Mutex
	kvStore := make(map[string]string)
	currentTxID := uint64(0)
	currentHash := sha256.Sum256([]byte("genesis_state"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.URL.Path == "/api/v1/login" && r.Method == http.MethodPost:
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["user"] != "immudb" || req["password"] != "immudb" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("invalid credentials"))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "test-session-token-xyz"})

		case r.URL.Path == "/health":
			if r.Header.Get("sessionid") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)

		case strings.HasSuffix(r.URL.Path, "/set") && r.Method == http.MethodPost:
			var req struct {
				KVs []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"kvs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			currentTxID++
			h := sha256.New()
			h.Write(currentHash[:])
			for _, item := range req.KVs {
				kvStore[item.Key] = item.Value
				h.Write([]byte(item.Key))
				h.Write([]byte(item.Value))
			}
			currentHash = [32]byte(h.Sum(nil))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   currentTxID,
				"hash": hex.EncodeToString(currentHash[:]),
			})

		case strings.HasSuffix(r.URL.Path, "/state") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"txId":   currentTxID,
				"txHash": hex.EncodeToString(currentHash[:]),
			})

		case strings.Contains(r.URL.Path, "/key/") && r.Method == http.MethodGet:
			parts := strings.Split(r.URL.Path, "/")
			b64Key := parts[len(parts)-1]
			val, ok := kvStore[b64Key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": val})

		case strings.HasSuffix(r.URL.Path, "/scan") && r.Method == http.MethodPost:
			var scanReq struct {
				Prefix string `json:"prefix"`
			}
			_ = json.NewDecoder(r.Body).Decode(&scanReq)
			prefixBytes, _ := base64.StdEncoding.DecodeString(scanReq.Prefix)
			prefixStr := string(prefixBytes)

			var entries []map[string]string
			for k, v := range kvStore {
				kBytes, _ := base64.StdEncoding.DecodeString(k)
				if strings.HasPrefix(string(kBytes), prefixStr) {
					entries = append(entries, map[string]string{
						"key":   k,
						"value": v,
					})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entries": entries,
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	client := NewRealImmudbClient(ImmudbConfig{
		Address:     u.Hostname(),
		Port:        port,
		Username:    "immudb",
		Password:    "immudb",
		Database:    "defaultdb",
		DialTimeout: 2 * time.Second,
	})

	ctx := context.Background()
	if err := client.Open(ctx); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer client.Close(ctx)

	if err := client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	// 1. Initial State
	txID, root, err := client.GetLatestState(ctx)
	if err != nil {
		t.Fatalf("GetLatestState failed: %v", err)
	}
	if txID != 0 {
		t.Errorf("Expected initial TxID=0, got %d", txID)
	}
	if len(root) != 32 {
		t.Fatalf("Expected 32-byte initial root hash, got %d", len(root))
	}

	// 2. Commit batch of events
	events := []*AuditEventEnvelope{
		{
			EventID:       "ev-real-1",
			CorrelationID: "corr-real-100",
			AISystemID:    "loan-evaluator",
			OutputPayload: "DECISION_OK",
			Timestamp:     time.Now().UTC(),
		},
		{
			EventID:       "ev-real-2",
			CorrelationID: "corr-real-100",
			AISystemID:    "loan-evaluator",
			OutputPayload: "DECISION_WARN",
			Timestamp:     time.Now().UTC(),
		},
	}

	commitRes, err := client.CommitBatch(ctx, events)
	if err != nil {
		t.Fatalf("CommitBatch failed: %v", err)
	}
	if commitRes.TxID != 1 {
		t.Errorf("Expected TxID=1, got %d", commitRes.TxID)
	}
	if commitRes.EventCount != 2 {
		t.Errorf("Expected EventCount=2, got %d", commitRes.EventCount)
	}
	if len(commitRes.RootHash) != 32 || bytes.Equal(commitRes.RootHash, make([]byte, 32)) {
		t.Errorf("RootHash must be a non-zero 32-byte cryptographic hash")
	}

	// 3. Retrieve event by ID
	retrieved, err := client.GetEvent(ctx, "ev-real-1")
	if err != nil {
		t.Fatalf("GetEvent failed: %v", err)
	}
	if retrieved.OutputPayload != "DECISION_OK" {
		t.Errorf("Expected payload DECISION_OK, got %s", retrieved.OutputPayload)
	}

	// 4. Retrieve events by correlation ID
	corrEvents, err := client.GetEventsByCorrelation(ctx, "corr-real-100")
	if err != nil {
		t.Fatalf("GetEventsByCorrelation failed: %v", err)
	}
	if len(corrEvents) != 2 {
		t.Errorf("Expected 2 events matching correlation ID, got %d", len(corrEvents))
	}

	// 5. Save and retrieve anchor record
	anchor := &AnchorRecord{
		AnchorID:       "anc-real-001",
		ImmudbTxID:     1,
		ImmudbRootHash: hex.EncodeToString(commitRes.RootHash),
		Status:         "VALID",
		CreatedAt:      time.Now().UTC(),
	}
	if err := client.SaveAnchor(ctx, anchor); err != nil {
		t.Fatalf("SaveAnchor failed: %v", err)
	}

	latestAnchor, err := client.GetLatestAnchor(ctx)
	if err != nil {
		t.Fatalf("GetLatestAnchor failed: %v", err)
	}
	if latestAnchor.AnchorID != "anc-real-001" {
		t.Errorf("Expected AnchorID anc-real-001, got %s", latestAnchor.AnchorID)
	}

	byID, err := client.GetAnchorByID(ctx, "anc-real-001")
	if err != nil {
		t.Fatalf("GetAnchorByID failed: %v", err)
	}
	if byID.ImmudbRootHash != anchor.ImmudbRootHash {
		t.Errorf("Expected root hash %s, got %s", anchor.ImmudbRootHash, byID.ImmudbRootHash)
	}

	// 6. Empty batch commit returns latest state
	emptyRes, err := client.CommitBatch(ctx, []*AuditEventEnvelope{})
	if err != nil {
		t.Fatalf("CommitBatch empty failed: %v", err)
	}
	if emptyRes.TxID != 2 {
		t.Errorf("Expected TxID=2 for empty batch, got %d", emptyRes.TxID)
	}
}

func TestRealImmudbClient_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad username or password"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	client := NewRealImmudbClient(ImmudbConfig{
		Address:  u.Hostname(),
		Port:     port,
		Username: "wrong",
		Password: "wrong",
	})

	ctx := context.Background()
	if err := client.Open(ctx); err == nil {
		t.Errorf("Expected Open to fail with 401 Unauthorized")
	}
}

func TestRealImmudbClient_ServerErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "dummy-token"})
		case strings.HasSuffix(r.URL.Path, "/set"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal database storage error"))
		case strings.Contains(r.URL.Path, "/key/"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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

	// CommitBatch should fail on 500
	events := []*AuditEventEnvelope{
		{EventID: "fail-ev-1", Timestamp: time.Now().UTC()},
	}
	if _, err := client.CommitBatch(ctx, events); err == nil {
		t.Errorf("Expected CommitBatch to fail on HTTP 500")
	}

	// GetEvent should fail on 404
	if _, err := client.GetEvent(ctx, "nonexistent"); err == nil {
		t.Errorf("Expected GetEvent to fail on 404")
	}

	// GetLatestAnchor should fail on 404
	if _, err := client.GetLatestAnchor(ctx); err == nil {
		t.Errorf("Expected GetLatestAnchor to fail on 404")
	}
}
