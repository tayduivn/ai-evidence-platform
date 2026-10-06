package ledger

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AnchorService orchestrates periodic state root anchoring to an RFC 3161 TSA.
type AnchorService interface {
	AnchorCurrentRoot(ctx context.Context, force bool) (*AnchorRecord, error)
	GetLatestAnchor(ctx context.Context) (*AnchorRecord, error)
	GetAnchorByID(ctx context.Context, anchorID string) (*AnchorRecord, error)
	VerifyAnchor(ctx context.Context, rootHash []byte, tokenB64 string) (bool, time.Time, error)
	StartPeriodicAnchoring(ctx context.Context, interval time.Duration)
	Stop()
}

// DefaultAnchorService implements AnchorService.
type DefaultAnchorService struct {
	client     ImmudbClient
	tsaClient  *RFC3161Client
	tree       MerkleTree
	mu         sync.RWMutex
	running    bool
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	lastTxID   uint64
	lastRoot   []byte
	lastAnchor *AnchorRecord
}

// NewAnchorService creates an initialized AnchorService.
func NewAnchorService(client ImmudbClient, tsaClient *RFC3161Client, tree MerkleTree) *DefaultAnchorService {
	return &DefaultAnchorService{
		client:    client,
		tsaClient: tsaClient,
		tree:      tree,
	}
}

// AnchorCurrentRoot samples the latest ledger state root and seals it via the TSA.
func (s *DefaultAnchorService) AnchorCurrentRoot(ctx context.Context, force bool) (*AnchorRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	txID, rootHash, err := s.client.GetLatestState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve immudb state: %w", err)
	}

	// If rootHash from immudb is empty or zero, fallback to MerkleTree root
	if len(rootHash) == 0 || bytes.Equal(rootHash, make([]byte, len(rootHash))) {
		if s.tree != nil {
			treeRoot := s.tree.Root()
			rootHash = treeRoot[:]
		}
	}

	// Idempotency check: Skip external call if state root has not changed since last anchor
	if !force && s.lastAnchor != nil && s.lastTxID == txID && bytes.Equal(s.lastRoot, rootHash) {
		return s.lastAnchor, nil
	}

	respDER, tstInfo, tsaCert, err := s.tsaClient.RequestTimestamp(ctx, rootHash)
	if err != nil {
		return nil, fmt.Errorf("tsa anchoring request failed: %w", err)
	}

	certSerial := ""
	if tsaCert != nil && tsaCert.SerialNumber != nil {
		certSerial = tsaCert.SerialNumber.String()
	}

	anchorID := fmt.Sprintf("anc-%d-%s", txID, time.Now().UTC().Format("20060102150405"))
	record := &AnchorRecord{
		AnchorID:          anchorID,
		ImmudbTxID:        txID,
		ImmudbRootHash:    hex.EncodeToString(rootHash),
		TSAURL:            s.tsaClient.config.PrimaryURL,
		TSACertSerial:     certSerial,
		TimestampTokenB64: base64.StdEncoding.EncodeToString(respDER),
		VerifiedGenTime:   tstInfo.GenTime,
		Status:            "VALID",
		CreatedAt:         time.Now().UTC(),
	}

	if err := s.client.SaveAnchor(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to persist anchor record: %w", err)
	}

	s.lastTxID = txID
	s.lastRoot = rootHash
	s.lastAnchor = record

	return record, nil
}

// GetLatestAnchor retrieves the most recent anchor record.
func (s *DefaultAnchorService) GetLatestAnchor(ctx context.Context) (*AnchorRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client.GetLatestAnchor(ctx)
}

// GetAnchorByID retrieves a specific anchor by ID.
func (s *DefaultAnchorService) GetAnchorByID(ctx context.Context, anchorID string) (*AnchorRecord, error) {
	return s.client.GetAnchorByID(ctx, anchorID)
}

// VerifyAnchor validates a base64-encoded TSR token against a root hash.
func (s *DefaultAnchorService) VerifyAnchor(ctx context.Context, rootHash []byte, tokenB64 string) (bool, time.Time, error) {
	respDER, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("invalid base64 token: %w", err)
	}

	tstInfo, _, err := s.tsaClient.ValidateResponse(respDER, rootHash, nil)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("verification failed: %w", err)
	}

	return true, tstInfo.GenTime, nil
}

// StartPeriodicAnchoring starts background cron anchoring.
func (s *DefaultAnchorService) StartPeriodicAnchoring(ctx context.Context, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true

	cronCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-cronCtx.Done():
				return
			case <-ticker.C:
				anchorCtx, c := context.WithTimeout(cronCtx, 15*time.Second)
				_, _ = s.AnchorCurrentRoot(anchorCtx, false)
				c()
			}
		}
	}()
}

// Stop stops the background periodic cron.
func (s *DefaultAnchorService) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// AnchorHTTPHandler provides REST API endpoints for anchor management.
type AnchorHTTPHandler struct {
	anchorService AnchorService
	worker        *MicroBatchWorker
}

// NewAnchorHTTPHandler creates an HTTP handler for ledger API routes.
func NewAnchorHTTPHandler(anchorService AnchorService, worker *MicroBatchWorker) http.Handler {
	mux := http.NewServeMux()
	h := &AnchorHTTPHandler{
		anchorService: anchorService,
		worker:        worker,
	}

	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/api/v1/ledger/anchors/latest", h.handleLatestAnchor)
	mux.HandleFunc("/api/v1/ledger/anchors/trigger", h.handleTriggerAnchor)
	mux.HandleFunc("/api/v1/ledger/anchors/verify", h.handleVerifyAnchor)
	mux.HandleFunc("/api/v1/ledger/anchors/", h.handleAnchorByID)

	return mux
}

func (h *AnchorHTTPHandler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var health HealthStatus
	if h.worker != nil {
		health = h.worker.Health(ctx)
	} else {
		health = HealthStatus{Status: "UP", ImmudbStatus: "CONNECTED"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(health)
}

func (h *AnchorHTTPHandler) handleLatestAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	anchor, err := h.anchorService.GetLatestAnchor(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(anchor)
}

func (h *AnchorHTTPHandler) handleTriggerAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	record, err := h.anchorService.AnchorCurrentRoot(r.Context(), req.Force)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(record)
}

func (h *AnchorHTTPHandler) handleVerifyAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RootHash          string `json:"root_hash"`
		TimestampTokenB64 string `json:"timestamp_token_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	rootBytes, err := hex.DecodeString(req.RootHash)
	if err != nil || len(rootBytes) != 32 {
		http.Error(w, "Invalid root_hash hex string", http.StatusBadRequest)
		return
	}

	valid, genTime, err := h.anchorService.VerifyAnchor(r.Context(), rootBytes, req.TimestampTokenB64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    valid,
		"gen_time": genTime,
	})
}

func (h *AnchorHTTPHandler) handleAnchorByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/ledger/anchors/")
	if path == "" {
		http.Error(w, "Anchor ID required", http.StatusBadRequest)
		return
	}

	if strings.HasSuffix(path, "/download") {
		anchorID := strings.TrimSuffix(path, "/download")
		anchor, err := h.anchorService.GetAnchorByID(r.Context(), anchorID)
		if err != nil {
			http.Error(w, "Anchor not found", http.StatusNotFound)
			return
		}

		rawDER, err := base64.StdEncoding.DecodeString(anchor.TimestampTokenB64)
		if err != nil {
			http.Error(w, "Corrupted token payload", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tsr", anchorID))
		_, _ = w.Write(rawDER)
		return
	}

	anchor, err := h.anchorService.GetAnchorByID(r.Context(), path)
	if err != nil {
		http.Error(w, "Anchor not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(anchor)
}
