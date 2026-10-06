package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

type RemoteAuthMode string

const (
	RemoteAuthAutoApprove RemoteAuthMode = "AUTO_APPROVE"
	RemoteAuthRequireOTP  RemoteAuthMode = "REQUIRE_OTP"
	RemoteAuthSimTimeout  RemoteAuthMode = "SIMULATE_TIMEOUT"
)

// CAVNRemoteConfig holds configuration for the Remote Signing / CSC API client.
type CAVNRemoteConfig struct {
	BaseURL        string        // If empty, uses embedded MockRemoteCAServer
	ClientID       string
	ClientSecret   string
	CredentialID   string
	AuthMode       RemoteAuthMode
	FixedOTP       string        // default "123456"
	Timeout        time.Duration // default 5s
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	RootCAPEM      []byte
}

// CAVNRemoteSigner implements Circular 16/2019 / CSC API Remote Signing simulator.
type CAVNRemoteSigner struct {
	mu         sync.RWMutex
	config     CAVNRemoteConfig
	token      string
	tokenExp   time.Time
	privateKey *rsa.PrivateKey
	certPEM    []byte
	chainPEM   [][]byte
	mockServer *httptest.Server
	httpClient *http.Client
}

// NewCAVNRemoteSigner constructs a Remote Signing client.
func NewCAVNRemoteSigner(cfg CAVNRemoteConfig) (*CAVNRemoteSigner, error) {
	if cfg.ClientID == "" {
		cfg.ClientID = "ei-approval-service"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = "secret-vnpt-smartca-2026"
	}
	if cfg.CredentialID == "" {
		cfg.CredentialID = "cred-cloud-hsm-99182"
	}
	if cfg.FixedOTP == "" {
		cfg.FixedOTP = "123456"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = RemoteAuthAutoApprove
	}

	s := &CAVNRemoteSigner{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	// Prepare key and certificate
	if len(cfg.PrivateKeyPEM) > 0 && len(cfg.CertificatePEM) > 0 {
		block, _ := pem.Decode(cfg.PrivateKeyPEM)
		if block == nil {
			return nil, errors.New("ca_vn_remote: invalid private key PEM")
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err8 != nil {
				return nil, fmt.Errorf("ca_vn_remote: parse private key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("ca_vn_remote: key is not RSA")
			}
			priv = rsaKey
		}
		s.privateKey = priv
		s.certPEM = cfg.CertificatePEM
	} else {
		// Generate remote HSM RSA key and cert
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("ca_vn_remote: RSA generation error: %w", err)
		}
		s.privateKey = priv
		subject := pkix.Name{
			Country:      []string{"VN"},
			Organization: []string{"VNPT SmartCA Cloud HSM"},
			CommonName:   "Ký Số Từ Xa VNPT SmartCA",
		}
		certPEM, _, err := generateX509Cert(priv, subject, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment)
		if err != nil {
			return nil, fmt.Errorf("ca_vn_remote: cert generation error: %w", err)
		}
		s.certPEM = certPEM
	}

	s.chainPEM = [][]byte{s.certPEM}
	if len(cfg.RootCAPEM) > 0 {
		s.chainPEM = append(s.chainPEM, cfg.RootCAPEM)
	}

	// If BaseURL is empty, spin up embedded mock server
	if cfg.BaseURL == "" {
		s.mockServer = s.createMockServer()
		s.config.BaseURL = s.mockServer.URL
	}

	return s, nil
}

func (s *CAVNRemoteSigner) Type() string {
	return "ca_vn_remote"
}

func (s *CAVNRemoteSigner) Close() {
	if s.mockServer != nil {
		s.mockServer.Close()
	}
}

func (s *CAVNRemoteSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if s.config.AuthMode == RemoteAuthSimTimeout {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return nil, nil, ErrRemoteTimeout
		}
	}

	// 1. Ensure Bearer token
	token, err := s.getBearerToken(ctx)
	if err != nil {
		return nil, nil, err
	}

	// 2. Compute digest
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])

	// 3. Dispatch signHash request to remote endpoint
	reqBody := map[string]interface{}{
		"credential_id":  s.config.CredentialID,
		"hash":           digestHex,
		"hash_algorithm": "SHA-256",
		"sign_algorithm": "RSA-SHA256",
		"otp":            s.config.FixedOTP,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.BaseURL+"/api/v1/signatures/signHash", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("ca_vn_remote: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, nil, ErrRemoteAuthFailed
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, nil, ErrInvalidOTP
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("ca_vn_remote: remote server returned %d", resp.StatusCode)
	}

	var signResp struct {
		SignatureHex string `json:"signature_hex"`
		CertPEM      string `json:"cert_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, nil, fmt.Errorf("ca_vn_remote: decode error: %w", err)
	}

	sigBytes, err := hex.DecodeString(signResp.SignatureHex)
	if err != nil {
		return nil, nil, fmt.Errorf("ca_vn_remote: decode signature hex error: %w", err)
	}

	return sigBytes, s.certPEM, nil
}

func (s *CAVNRemoteSigner) Verify(ctx context.Context, payload []byte, signature []byte, certPEM []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, errors.New("ca_vn_remote: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("ca_vn_remote: parse cert error: %w", err)
	}

	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, ErrCertificateExpired
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("ca_vn_remote: public key is not RSA")
	}

	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature); err != nil {
		return false, ErrInvalidSignature
	}
	return true, nil
}

func (s *CAVNRemoteSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.chainPEM, nil
}

func (s *CAVNRemoteSigner) getBearerToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.token != "" && time.Now().Before(s.tokenExp) {
		tok := s.token
		s.mu.RUnlock()
		return tok, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check under write lock
	if s.token != "" && time.Now().Before(s.tokenExp) {
		return s.token, nil
	}

	authReq := map[string]string{
		"client_id":     s.config.ClientID,
		"client_secret": s.config.ClientSecret,
	}
	body, _ := json.Marshal(authReq)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.BaseURL+"/api/v1/auth/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ca_vn_remote: auth request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrRemoteAuthFailed
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	s.token = authResp.AccessToken
	expSec := authResp.ExpiresIn
	if expSec <= 0 {
		expSec = 3600
	}
	s.tokenExp = time.Now().Add(time.Duration(expSec-30) * time.Second)

	return s.token, nil
}

func (s *CAVNRemoteSigner) createMockServer() *httptest.Server {
	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["client_id"] != s.config.ClientID || req["client_secret"] != s.config.ClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-bearer-jwt-token-smartca",
			"expires_in":   3600,
		})
	})

	// SignHash endpoint
	mux.HandleFunc("/api/v1/signatures/signHash", func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr != "Bearer mock-bearer-jwt-token-smartca" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var req struct {
			CredentialID string `json:"credential_id"`
			Hash         string `json:"hash"`
			OTP          string `json:"otp"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// OTP validation if in RequireOTP mode
		if s.config.AuthMode == RemoteAuthRequireOTP && req.OTP != s.config.FixedOTP {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "INVALID_OTP"})
			return
		}

		hashBytes, err := hex.DecodeString(req.Hash)
		if err != nil || len(hashBytes) != 32 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashBytes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"signature_hex":  hex.EncodeToString(sig),
			"cert_pem":       string(s.certPEM),
			"transaction_id": "tx-smartca-2026-001",
		})
	})

	return httptest.NewServer(mux)
}
