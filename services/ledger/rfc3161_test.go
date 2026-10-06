package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestRFC3161_CreateTimeStampReq(t *testing.T) {
	// 1. Rejection on empty root hash
	if _, _, err := CreateTimeStampReq(nil, OIDPolicyDefaultMockTSA); err == nil {
		t.Errorf("Expected error on nil root hash")
	}
	if _, _, err := CreateTimeStampReq([]byte{}, OIDPolicyDefaultMockTSA); err == nil {
		t.Errorf("Expected error on empty root hash")
	}

	// 2. Successful request generation
	rootHash := sha256.Sum256([]byte("sample-state-root-tx-1"))
	reqDER, nonce, err := CreateTimeStampReq(rootHash[:], OIDPolicyDefaultMockTSA)
	if err != nil {
		t.Fatalf("CreateTimeStampReq failed: %v", err)
	}

	if len(reqDER) == 0 {
		t.Fatalf("Expected non-empty DER bytes")
	}
	if nonce == nil || nonce.Sign() <= 0 {
		t.Fatalf("Expected valid positive nonce")
	}

	// 3. Unmarshal and inspect ASN.1 structure
	var req TimeStampReq
	if _, err := asn1.Unmarshal(reqDER, &req); err != nil {
		t.Fatalf("Failed to unmarshal TimeStampReq: %v", err)
	}

	if req.Version != 1 {
		t.Errorf("Expected RFC 3161 Version=1, got %d", req.Version)
	}
	if !req.CertReq {
		t.Errorf("Expected CertReq=true")
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Errorf("Expected SHA-256 OID, got %v", req.MessageImprint.HashAlgorithm.Algorithm)
	}

	expectedImprint := sha256.Sum256(rootHash[:])
	if string(req.MessageImprint.HashedMessage) != string(expectedImprint[:]) {
		t.Errorf("Hashed message in TimeStampReq does not match SHA256(rootHash)")
	}
}

func TestRFC3161_MockTSA_Roundtrip(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	rootHash := sha256.Sum256([]byte("merkle-root-at-block-50"))

	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	ctx := context.Background()
	respDER, tstInfo, tsaCert, err := client.RequestTimestamp(ctx, rootHash[:])
	if err != nil {
		t.Fatalf("RequestTimestamp failed: %v", err)
	}

	if len(respDER) == 0 {
		t.Errorf("Expected non-empty DER response")
	}
	if tstInfo == nil {
		t.Fatalf("Expected non-nil TSTInfo")
	}
	if tstInfo.SerialNumber == nil || tstInfo.SerialNumber.Int64() < 1 {
		t.Errorf("Expected positive serial number in TSTInfo")
	}
	if tsaCert == nil {
		t.Errorf("Expected embedded TSA certificate")
	}

	// Verify timestamp is recent (within 5 seconds)
	if time.Since(tstInfo.GenTime) > 5*time.Second {
		t.Errorf("GenTime seems stale: %v", tstInfo.GenTime)
	}
}

func TestRFC3161_RejectionStatus(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	mockTSA.SetFailStatus(2) // Simulate TSA rejection

	rootHash := sha256.Sum256([]byte("state-root-tx-rejected"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash[:])
	if err == nil {
		t.Errorf("Expected error when TSA responds with rejection status")
	}
}

func TestRFC3161_NonceMismatch(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	rootHash := sha256.Sum256([]byte("state-root-tx-nonce"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	respDER, _, _, err := client.RequestTimestamp(context.Background(), rootHash[:])
	if err != nil {
		t.Fatalf("RequestTimestamp failed: %v", err)
	}

	// Validate against a forged nonce
	forgedNonce := big.NewInt(999999999)
	if _, _, err := client.ValidateResponse(respDER, rootHash[:], forgedNonce); err == nil {
		t.Errorf("Expected error validating response against mismatched nonce")
	}
}

func TestRFC3161_RootHashMismatch(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	rootHash := sha256.Sum256([]byte("state-root-original"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	respDER, _, _, err := client.RequestTimestamp(context.Background(), rootHash[:])
	if err != nil {
		t.Fatalf("RequestTimestamp failed: %v", err)
	}

	tamperedRoot := sha256.Sum256([]byte("state-root-tampered"))
	if _, _, err := client.ValidateResponse(respDER, tamperedRoot[:], nil); err == nil {
		t.Errorf("Expected error validating response against changed root hash")
	}
}

func TestRFC3161_CorruptSignature(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	mockTSA.SetCorruptSignature(true)

	rootHash := sha256.Sum256([]byte("state-root-corrupt-sig"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash[:])
	if err == nil {
		t.Errorf("Expected signature verification failure on corrupted signature")
	}
}

func TestRFC3161_CorruptImprint(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	mockTSA.SetCorruptImprint(true)

	rootHash := sha256.Sum256([]byte("state-root-corrupt-imprint"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash[:])
	if err == nil {
		t.Errorf("Expected error on corrupted message imprint")
	}
}

func TestRFC3161_FixedTime(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	fixed := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	mockTSA.SetFixedTime(fixed)

	rootHash := sha256.Sum256([]byte("state-root-fixed-time"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 2 * time.Second,
		MaxRetries:  1,
	})

	_, tstInfo, _, err := client.RequestTimestamp(context.Background(), rootHash[:])
	if err != nil {
		t.Fatalf("RequestTimestamp failed: %v", err)
	}

	if !tstInfo.GenTime.Equal(fixed) {
		t.Errorf("Expected GenTime %v, got %v", fixed, tstInfo.GenTime)
	}
}

func TestRFC3161_TimeoutAndRetries(t *testing.T) {
	mockTSA, err := NewMockTSAServer()
	if err != nil {
		t.Fatalf("NewMockTSAServer failed: %v", err)
	}
	defer mockTSA.Close()

	// Inject 200ms delay while client timeout is 30ms
	mockTSA.SetDelay(200 * time.Millisecond)

	rootHash := sha256.Sum256([]byte("state-root-timeout"))
	client := NewRFC3161Client(TSAClientConfig{
		PrimaryURL:  mockTSA.URL(),
		HTTPTimeout: 30 * time.Millisecond,
		MaxRetries:  2,
	})

	_, _, _, err = client.RequestTimestamp(context.Background(), rootHash[:])
	if err == nil {
		t.Errorf("Expected timeout error when TSA response exceeds timeout")
	}
}
