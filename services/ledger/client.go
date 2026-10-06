package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ImmudbConfig holds configuration parameters for the immudb connection.
type ImmudbConfig struct {
	Address     string        `json:"address"`
	Port        int           `json:"port"`
	Database    string        `json:"database"`
	Username    string        `json:"username"`
	Password    string        `json:"password"`
	MaxRetries  int           `json:"max_retries"`
	DialTimeout time.Duration `json:"dial_timeout"`
	KeepAlive   time.Duration `json:"keepalive_time"`
}

// ImmudbClient defines the interface for immudb interactions.
type ImmudbClient interface {
	Open(ctx context.Context) error
	Close(ctx context.Context) error
	HealthCheck(ctx context.Context) error
	CommitBatch(ctx context.Context, events []*AuditEventEnvelope) (*BatchCommitResult, error)
	GetLatestState(ctx context.Context) (uint64, []byte, error)
	GetEvent(ctx context.Context, eventID string) (*AuditEventEnvelope, error)
	GetEventsByCorrelation(ctx context.Context, correlationID string) ([]*AuditEventEnvelope, error)
	SaveAnchor(ctx context.Context, anchor *AnchorRecord) error
	GetLatestAnchor(ctx context.Context) (*AnchorRecord, error)
	GetAnchorByID(ctx context.Context, anchorID string) (*AnchorRecord, error)
}

// RealImmudbClient provides a production HTTP/REST connection client to an external immudb instance.
type RealImmudbClient struct {
	cfg        ImmudbConfig
	httpClient *http.Client
	baseURL    string
	authToken  string
	database   string
	mu         sync.RWMutex
	connected  bool
}

// NewRealImmudbClient creates a new client for a live immudb instance.
func NewRealImmudbClient(cfg ImmudbConfig) *RealImmudbClient {
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 3322
	}
	if cfg.Database == "" {
		cfg.Database = "defaultdb"
	}
	if cfg.Username == "" {
		cfg.Username = "immudb"
	}
	if cfg.Password == "" {
		cfg.Password = "immudb"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}

	return &RealImmudbClient{
		cfg:      cfg,
		database: cfg.Database,
		baseURL:  fmt.Sprintf("http://%s:%d", cfg.Address, cfg.Port),
		httpClient: &http.Client{
			Timeout: cfg.DialTimeout,
		},
	}
}

type immudbLoginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type immudbLoginResp struct {
	Token string `json:"token"`
}

// Open initiates an authenticated session to the immudb server.
func (c *RealImmudbClient) Open(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	loginURL := fmt.Sprintf("%s/api/v1/login", c.baseURL)
	payload, err := json.Marshal(immudbLoginReq{
		User:     c.cfg.Username,
		Password: c.cfg.Password,
	})
	if err != nil {
		return fmt.Errorf("failed to encode login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.connected = false
		return fmt.Errorf("failed to connect to immudb at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// Fallback to immudb native REST API: /api/login with base64 credentials
			b64User := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username))
			b64Pass := base64.StdEncoding.EncodeToString([]byte(c.cfg.Password))
			altPayload, _ := json.Marshal(map[string]string{
				"user":     b64User,
				"password": b64Pass,
			})
			altReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/login", c.baseURL), bytes.NewReader(altPayload))
			if err == nil {
				altReq.Header.Set("Content-Type", "application/json")
				if altResp, err := c.httpClient.Do(altReq); err == nil {
					defer altResp.Body.Close()
					if altResp.StatusCode == http.StatusOK {
						var altLoginResp immudbLoginResp
						if err := json.NewDecoder(altResp.Body).Decode(&altLoginResp); err == nil && altLoginResp.Token != "" {
							c.authToken = altLoginResp.Token
							c.connected = true
							return nil
						}
					}
				}
			}
		}
		c.connected = false
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("immudb login failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var loginResp immudbLoginResp
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		c.connected = false
		return fmt.Errorf("failed to decode immudb login response: %w", err)
	}

	c.authToken = loginResp.Token
	c.connected = true
	return nil
}

// Close closes the client connection and revokes credentials.
func (c *RealImmudbClient) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	c.authToken = ""
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}

// HealthCheck verifies connectivity and authenticated access to immudb.
func (c *RealImmudbClient) HealthCheck(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return errors.New("immudb client is not connected")
	}

	healthURL := fmt.Sprintf("%s/health", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}
	if c.authToken != "" {
		req.Header.Set("sessionid", c.authToken)
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("immudb health probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			// Fallback to immudb native endpoint probe
			altReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/docs", c.baseURL), nil)
			if err == nil {
				if altResp, err := c.httpClient.Do(altReq); err == nil {
					defer altResp.Body.Close()
					if altResp.StatusCode == http.StatusOK {
						return nil
					}
				}
			}
		}
		return fmt.Errorf("immudb unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

type immudbKV struct {
	Key   string `json:"key"`   // base64 encoded
	Value string `json:"value"` // base64 encoded
}

type immudbSetRequest struct {
	KVs []immudbKV `json:"kvs"`
}

type immudbTxResponse struct {
	ID   uint64 `json:"id"`
	Hash string `json:"hash"` // hex or base64
}

// CommitBatch commits an atomic batch of audit events to immudb Key-Value storage.
func (c *RealImmudbClient) CommitBatch(ctx context.Context, events []*AuditEventEnvelope) (*BatchCommitResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, errors.New("cannot commit batch: immudb client is not connected")
	}

	if len(events) == 0 {
		txID, root, err := c.getLatestStateLocked(ctx)
		if err != nil {
			return nil, err
		}
		return &BatchCommitResult{
			TxID:        txID,
			RootHash:    root,
			CommittedAt: time.Now().UTC(),
			EventCount:  0,
		}, nil
	}

	kvs := make([]immudbKV, 0, len(events)*2)
	for _, ev := range events {
		if ev == nil {
			continue
		}
		evJSON, err := json.Marshal(ev)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal event %s: %w", ev.EventID, err)
		}

		// Primary Key: event:<event_id>
		kvs = append(kvs, immudbKV{
			Key:   base64.StdEncoding.EncodeToString([]byte("event:" + ev.EventID)),
			Value: base64.StdEncoding.EncodeToString(evJSON),
		})

		// Correlation Index Key: corr:<correlation_id>:<event_id>
		if ev.CorrelationID != "" {
			kvs = append(kvs, immudbKV{
				Key:   base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("corr:%s:%s", ev.CorrelationID, ev.EventID))),
				Value: base64.StdEncoding.EncodeToString([]byte(ev.EventID)),
			})
		}
	}

	setURL := fmt.Sprintf("%s/api/v1/ledger/%s/set", c.baseURL, c.database)
	reqBody, err := json.Marshal(immudbSetRequest{KVs: kvs})
	if err != nil {
		return nil, fmt.Errorf("failed to encode set request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, setURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create set request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("immudb batch set failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("immudb batch set error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var txResp immudbTxResponse
	if err := json.NewDecoder(resp.Body).Decode(&txResp); err != nil {
		return nil, fmt.Errorf("failed to decode transaction response: %w", err)
	}

	var rootHash []byte
	if txResp.Hash != "" {
		if decoded, err := hex.DecodeString(txResp.Hash); err == nil && len(decoded) == 32 {
			rootHash = decoded
		} else if b64Dec, err := base64.StdEncoding.DecodeString(txResp.Hash); err == nil && len(b64Dec) == 32 {
			rootHash = b64Dec
		}
	}

	// If root hash wasn't in transaction response, fetch the state root
	if len(rootHash) == 0 {
		_, stateRoot, err := c.getLatestStateLocked(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to query state root following commit: %w", err)
		}
		rootHash = stateRoot
	}

	return &BatchCommitResult{
		TxID:        txResp.ID,
		RootHash:    rootHash,
		CommittedAt: time.Now().UTC(),
		EventCount:  len(events),
	}, nil
}

type immudbStateResponse struct {
	TxID   uint64 `json:"txId"`
	TxHash string `json:"txHash"`
}

func (c *RealImmudbClient) getLatestStateLocked(ctx context.Context) (uint64, []byte, error) {
	stateURL := fmt.Sprintf("%s/api/v1/ledger/%s/state", c.baseURL, c.database)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stateURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get state: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, nil, fmt.Errorf("failed to get state (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var stateResp immudbStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&stateResp); err != nil {
		return 0, nil, fmt.Errorf("failed to decode state response: %w", err)
	}

	var rootHash []byte
	if stateResp.TxHash != "" {
		if decoded, err := hex.DecodeString(stateResp.TxHash); err == nil && len(decoded) == 32 {
			rootHash = decoded
		} else if b64, err := base64.StdEncoding.DecodeString(stateResp.TxHash); err == nil && len(b64) == 32 {
			rootHash = b64
		}
	}
	if len(rootHash) == 0 {
		empty := sha256.Sum256([]byte("genesis"))
		rootHash = empty[:]
	}

	return stateResp.TxID, rootHash, nil
}

// GetLatestState returns the latest transaction sequence number and state root hash.
func (c *RealImmudbClient) GetLatestState(ctx context.Context) (uint64, []byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return 0, nil, errors.New("immudb not connected")
	}
	return c.getLatestStateLocked(ctx)
}

type immudbKeyResponse struct {
	Value string `json:"value"` // base64 encoded
}

// GetEvent retrieves a specific audit event by event ID.
func (c *RealImmudbClient) GetEvent(ctx context.Context, eventID string) (*AuditEventEnvelope, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, errors.New("immudb not connected")
	}

	b64Key := base64.StdEncoding.EncodeToString([]byte("event:" + eventID))
	keyURL := fmt.Sprintf("%s/api/v1/ledger/%s/key/%s", c.baseURL, c.database, b64Key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get event key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("event %s not found", eventID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get event (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var keyResp immudbKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode event value: %w", err)
	}

	rawJSON, err := base64.StdEncoding.DecodeString(keyResp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode event: %w", err)
	}

	var event AuditEventEnvelope
	if err := json.Unmarshal(rawJSON, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event envelope: %w", err)
	}

	return &event, nil
}

type immudbScanRequest struct {
	Prefix string `json:"prefix"` // base64
}

type immudbScanResponse struct {
	Entries []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"entries"`
}

// GetEventsByCorrelation returns all audit events matching a correlation ID.
func (c *RealImmudbClient) GetEventsByCorrelation(ctx context.Context, correlationID string) ([]*AuditEventEnvelope, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, errors.New("immudb not connected")
	}

	scanURL := fmt.Sprintf("%s/api/v1/ledger/%s/scan", c.baseURL, c.database)
	prefix := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("corr:%s:", correlationID)))
	reqBody, _ := json.Marshal(immudbScanRequest{Prefix: prefix})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scanURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to scan correlation index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan correlation failed: HTTP %d", resp.StatusCode)
	}

	var scanResp immudbScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode scan entries: %w", err)
	}

	events := make([]*AuditEventEnvelope, 0, len(scanResp.Entries))
	for _, entry := range scanResp.Entries {
		eventIDBytes, err := base64.StdEncoding.DecodeString(entry.Value)
		if err != nil {
			continue
		}
		eventID := string(eventIDBytes)
		ev, err := c.GetEvent(ctx, eventID)
		if err == nil && ev != nil {
			events = append(events, ev)
		}
	}

	return events, nil
}

// SaveAnchor persists an RFC 3161 anchor record to immudb.
func (c *RealImmudbClient) SaveAnchor(ctx context.Context, anchor *AnchorRecord) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return errors.New("immudb not connected")
	}
	if anchor == nil {
		return errors.New("anchor cannot be nil")
	}

	anchorData, err := json.Marshal(anchor)
	if err != nil {
		return fmt.Errorf("failed to marshal anchor: %w", err)
	}

	kvs := []immudbKV{
		{
			Key:   base64.StdEncoding.EncodeToString([]byte("anchor:" + anchor.AnchorID)),
			Value: base64.StdEncoding.EncodeToString(anchorData),
		},
		{
			Key:   base64.StdEncoding.EncodeToString([]byte("anchor:latest")),
			Value: base64.StdEncoding.EncodeToString(anchorData),
		},
	}

	setURL := fmt.Sprintf("%s/api/v1/ledger/%s/set", c.baseURL, c.database)
	reqBody, _ := json.Marshal(immudbSetRequest{KVs: kvs})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, setURL, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to save anchor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to save anchor (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetLatestAnchor returns the most recently stored anchor record.
func (c *RealImmudbClient) GetLatestAnchor(ctx context.Context) (*AnchorRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, errors.New("immudb not connected")
	}

	b64Key := base64.StdEncoding.EncodeToString([]byte("anchor:latest"))
	keyURL := fmt.Sprintf("%s/api/v1/ledger/%s/key/%s", c.baseURL, c.database, b64Key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest anchor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("no anchors found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get anchor: HTTP %d", resp.StatusCode)
	}

	var keyResp immudbKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode anchor value: %w", err)
	}

	rawJSON, err := base64.StdEncoding.DecodeString(keyResp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode anchor: %w", err)
	}

	var anchor AnchorRecord
	if err := json.Unmarshal(rawJSON, &anchor); err != nil {
		return nil, fmt.Errorf("failed to unmarshal anchor record: %w", err)
	}

	return &anchor, nil
}

// GetAnchorByID retrieves an anchor record by anchor ID.
func (c *RealImmudbClient) GetAnchorByID(ctx context.Context, anchorID string) (*AnchorRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, errors.New("immudb not connected")
	}

	b64Key := base64.StdEncoding.EncodeToString([]byte("anchor:" + anchorID))
	keyURL := fmt.Sprintf("%s/api/v1/ledger/%s/key/%s", c.baseURL, c.database, b64Key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("sessionid", c.authToken)
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get anchor by ID: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("anchor %s not found", anchorID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get anchor: HTTP %d", resp.StatusCode)
	}

	var keyResp immudbKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode anchor value: %w", err)
	}

	rawJSON, err := base64.StdEncoding.DecodeString(keyResp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode anchor: %w", err)
	}

	var anchor AnchorRecord
	if err := json.Unmarshal(rawJSON, &anchor); err != nil {
		return nil, fmt.Errorf("failed to unmarshal anchor record: %w", err)
	}

	return &anchor, nil
}
