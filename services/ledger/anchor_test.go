package ledger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnchorService_AnchorCurrentRoot(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()

	// Commit some events so state root is non-trivial
	ctx := context.Background()
	_, _ = client.CommitBatch(ctx, []*AuditEventEnvelope{
		{EventID: "anchor-ev-1", OutputPayload: "DECISION_OK", Timestamp: time.Now().UTC()},
	})

	tsaClient := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	service := NewAnchorService(client, tsaClient, tree)

	anchor, err := service.AnchorCurrentRoot(ctx, false)
	if err != nil {
		t.Fatalf("AnchorCurrentRoot failed: %v", err)
	}

	if anchor.Status != "VALID" {
		t.Errorf("Expected anchor status 'VALID', got %s", anchor.Status)
	}
	if anchor.ImmudbTxID != 1 {
		t.Errorf("Expected ImmudbTxID=1, got %d", anchor.ImmudbTxID)
	}
	if anchor.TimestampTokenB64 == "" {
		t.Errorf("Expected non-empty base64 timestamp token")
	}

	// Verify it can be retrieved as latest
	latest, err := service.GetLatestAnchor(ctx)
	if err != nil {
		t.Fatalf("GetLatestAnchor failed: %v", err)
	}
	if latest.AnchorID != anchor.AnchorID {
		t.Errorf("Latest anchor mismatch")
	}
}

func TestAnchorService_Deduplication(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()
	ctx := context.Background()

	_, _ = client.CommitBatch(ctx, []*AuditEventEnvelope{
		{EventID: "dedup-ev-1", OutputPayload: "VALUE", Timestamp: time.Now().UTC()},
	})

	tsaClient := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	service := NewAnchorService(client, tsaClient, tree)

	// First anchor
	anc1, err := service.AnchorCurrentRoot(ctx, false)
	if err != nil {
		t.Fatalf("First anchor failed: %v", err)
	}

	// Second anchor with unchanged root should deduplicate and return anc1
	anc2, err := service.AnchorCurrentRoot(ctx, false)
	if err != nil {
		t.Fatalf("Second anchor failed: %v", err)
	}
	if anc1.AnchorID != anc2.AnchorID {
		t.Errorf("Expected identical anchor ID on deduplicated call")
	}

	// Force anchor should produce new anchor
	anc3, err := service.AnchorCurrentRoot(ctx, true)
	if err != nil {
		t.Fatalf("Forced anchor failed: %v", err)
	}
	if anc3 == nil {
		t.Fatalf("Expected non-nil forced anchor")
	}
}

func TestAnchorService_VerifyAnchor(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()
	ctx := context.Background()

	_, _ = client.CommitBatch(ctx, []*AuditEventEnvelope{
		{EventID: "verify-ev-1", OutputPayload: "DATA", Timestamp: time.Now().UTC()},
	})

	tsaClient := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	service := NewAnchorService(client, tsaClient, tree)

	anchor, err := service.AnchorCurrentRoot(ctx, false)
	if err != nil {
		t.Fatalf("AnchorCurrentRoot failed: %v", err)
	}

	rootBytes, _ := hex.DecodeString(anchor.ImmudbRootHash)

	// Valid verify
	valid, genTime, err := service.VerifyAnchor(ctx, rootBytes, anchor.TimestampTokenB64)
	if err != nil || !valid {
		t.Fatalf("VerifyAnchor failed: valid=%v, err=%v", valid, err)
	}
	if genTime.IsZero() {
		t.Errorf("Expected non-zero genTime")
	}

	// Verify against tampered root
	tamperedRoot := make([]byte, len(rootBytes))
	copy(tamperedRoot, rootBytes)
	tamperedRoot[0] ^= 0xFF

	validWrong, _, err := service.VerifyAnchor(ctx, tamperedRoot, anchor.TimestampTokenB64)
	if validWrong || err == nil {
		t.Errorf("Expected verification failure on tampered root")
	}
}

func TestAnchorService_HTTPHandler(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()
	ctx := context.Background()

	_, _ = client.CommitBatch(ctx, []*AuditEventEnvelope{
		{EventID: "http-ev-1", OutputPayload: "HTTP_PAYLOAD", Timestamp: time.Now().UTC()},
	})

	tsaClient := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	service := NewAnchorService(client, tsaClient, tree)
	handler := NewAnchorHTTPHandler(service, nil)

	// 1. Healthz endpoint
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealth := httptest.NewRecorder()
	handler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 on /healthz, got %d", recHealth.Code)
	}

	// 2. Trigger anchor POST
	reqTrigger := httptest.NewRequest(http.MethodPost, "/api/v1/ledger/anchors/trigger", bytes.NewBufferString(`{"force": true}`))
	recTrigger := httptest.NewRecorder()
	handler.ServeHTTP(recTrigger, reqTrigger)
	if recTrigger.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201 on trigger, got %d: %s", recTrigger.Code, recTrigger.Body.String())
	}

	var createdAnchor AnchorRecord
	if err := json.Unmarshal(recTrigger.Body.Bytes(), &createdAnchor); err != nil {
		t.Fatalf("Failed to parse trigger response: %v", err)
	}

	// 3. Get latest anchor GET
	reqLatest := httptest.NewRequest(http.MethodGet, "/api/v1/ledger/anchors/latest", nil)
	recLatest := httptest.NewRecorder()
	handler.ServeHTTP(recLatest, reqLatest)
	if recLatest.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 on /latest, got %d", recLatest.Code)
	}

	// 4. Get anchor by ID GET
	reqByID := httptest.NewRequest(http.MethodGet, "/api/v1/ledger/anchors/"+createdAnchor.AnchorID, nil)
	recByID := httptest.NewRecorder()
	handler.ServeHTTP(recByID, reqByID)
	if recByID.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 on /anchors/{id}, got %d", recByID.Code)
	}

	// 5. Download anchor .tsr
	reqDownload := httptest.NewRequest(http.MethodGet, "/api/v1/ledger/anchors/"+createdAnchor.AnchorID+"/download", nil)
	recDownload := httptest.NewRecorder()
	handler.ServeHTTP(recDownload, reqDownload)
	if recDownload.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 on download, got %d", recDownload.Code)
	}
	if recDownload.Header().Get("Content-Type") != "application/timestamp-reply" {
		t.Errorf("Expected application/timestamp-reply content-type")
	}

	// 6. Verify anchor POST
	verifyReqBody, _ := json.Marshal(map[string]string{
		"root_hash":           createdAnchor.ImmudbRootHash,
		"timestamp_token_b64": createdAnchor.TimestampTokenB64,
	})
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/v1/ledger/anchors/verify", bytes.NewReader(verifyReqBody))
	recVerify := httptest.NewRecorder()
	handler.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 on /verify, got %d", recVerify.Code)
	}
}

func TestAnchorService_StartPeriodic(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	client := NewMockImmudbClient()
	tree := NewMemoryMerkleTree()
	ctx := context.Background()

	_, _ = client.CommitBatch(ctx, []*AuditEventEnvelope{
		{EventID: "periodic-ev-1", OutputPayload: "PERIODIC_DATA", Timestamp: time.Now().UTC()},
	})

	tsaClient := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	service := NewAnchorService(client, tsaClient, tree)
	service.StartPeriodicAnchoring(ctx, 50*time.Millisecond)

	// Wait for periodic ticker to execute
	time.Sleep(150 * time.Millisecond)
	service.Stop()

	latest, err := service.GetLatestAnchor(ctx)
	if err != nil {
		t.Fatalf("Expected anchor to be recorded by periodic cron: %v", err)
	}
	if latest == nil || latest.Status != "VALID" {
		t.Errorf("Expected valid anchor from periodic cron")
	}
}
