package ledger

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"
)

// MockTSAServer implements an in-memory RFC 3161 compliant Time Stamping Authority for testing.
type MockTSAServer struct {
	PrivateKey     *rsa.PrivateKey
	Certificate    *x509.Certificate
	CertDER        []byte
	server         *httptest.Server
	serialSeq      atomic.Uint64
	mu             sync.RWMutex
	fixedTime      *time.Time
	delay          time.Duration
	failStatus     *int
	corruptSig     bool
	corruptImprint bool
}

// NewMockTSAServer creates and starts an in-process RFC 3161 HTTP server with an ephemeral RSA key.
func NewMockTSAServer() (*MockTSAServer, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Mock TSA RSA key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   "AI Evidence Platform Mock TSA",
			Organization: []string{"AI Evidence Internal Authority"},
			Country:      []string{"VN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to self-sign Mock TSA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mock TSA certificate: %w", err)
	}

	tsa := &MockTSAServer{
		PrivateKey:  privKey,
		Certificate: cert,
		CertDER:     certDER,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tsa", tsa.Handler)
	mux.HandleFunc("/", tsa.Handler)
	tsa.server = httptest.NewServer(mux)

	return tsa, nil
}

// URL returns the HTTP endpoint of the running Mock TSA server.
func (m *MockTSAServer) URL() string {
	return m.server.URL + "/tsa"
}

// Close stops the underlying HTTP server.
func (m *MockTSAServer) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// SetFixedTime freezes the generated timestamp to a specific moment.
func (m *MockTSAServer) SetFixedTime(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fixedTime = &t
}

// SetDelay introduces artificial processing latency for timeout testing.
func (m *MockTSAServer) SetDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = d
}

// SetFailStatus configures the TSA to respond with a non-zero PKIStatus.
func (m *MockTSAServer) SetFailStatus(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStatus = &status
}

// SetCorruptSignature toggles intentional signature corruption for tamper testing.
func (m *MockTSAServer) SetCorruptSignature(corrupt bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.corruptSig = corrupt
}

// SetCorruptImprint toggles intentional MessageImprint modification.
func (m *MockTSAServer) SetCorruptImprint(corrupt bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.corruptImprint = corrupt
}

// Handler handles incoming RFC 3161 HTTP POST requests.
func (m *MockTSAServer) Handler(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	delay := m.delay
	failStatus := m.failStatus
	fixedTime := m.fixedTime
	corruptSig := m.corruptSig
	corruptImprint := m.corruptImprint
	m.mu.RUnlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req TimeStampReq
	if _, err := asn1.Unmarshal(body, &req); err != nil {
		m.respondRejection(w, 2, "Invalid ASN.1 DER TimeStampReq")
		return
	}

	if failStatus != nil {
		m.respondRejection(w, *failStatus, "Simulated TSA Rejection")
		return
	}

	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		m.respondRejection(w, 2, "Unsupported hash algorithm; expected SHA-256")
		return
	}

	genTime := time.Now().UTC()
	if fixedTime != nil {
		genTime = fixedTime.UTC()
	}

	serial := m.serialSeq.Add(1)

	imprint := req.MessageImprint
	if corruptImprint && len(imprint.HashedMessage) > 0 {
		corrupted := make([]byte, len(imprint.HashedMessage))
		copy(corrupted, imprint.HashedMessage)
		corrupted[0] ^= 0xFF
		imprint.HashedMessage = corrupted
	}

	tstInfo := TSTInfo{
		Version:        1,
		Policy:         OIDPolicyDefaultMockTSA,
		MessageImprint: imprint,
		SerialNumber:   big.NewInt(int64(serial)),
		GenTime:        genTime,
		Nonce:          req.Nonce,
		Ordering:       false,
	}

	tstInfoDER, err := asn1.Marshal(tstInfo)
	if err != nil {
		http.Error(w, "Failed to marshal TSTInfo", http.StatusInternalServerError)
		return
	}

	eContentRaw, err := asn1.Marshal(tstInfoDER)
	if err != nil {
		http.Error(w, "Failed to marshal eContent", http.StatusInternalServerError)
		return
	}

	tstDigest := sha256.Sum256(tstInfoDER)
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.PrivateKey, crypto.SHA256, tstDigest[:])
	if err != nil {
		http.Error(w, "Failed to compute signature", http.StatusInternalServerError)
		return
	}

	if corruptSig && len(signature) > 0 {
		signature[0] ^= 0xFF
	}

	signerInfo := CMSSignerInfo{
		Version: 1,
		SID: CMSIssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: m.Certificate.RawIssuer},
			SerialNumber: m.Certificate.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm:  OIDSHA256,
			Parameters: asn1.NullRawValue,
		},
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm:  OIDSignatureSha256WithRSA,
			Parameters: asn1.NullRawValue,
		},
		Signature: signature,
	}

	signedData := CMSSignedData{
		Version: 3,
		DigestAlgorithms: []AlgorithmIdentifier{
			{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue},
		},
		EncapContentInfo: CMSEncapContentInfo{
			EContentType: OIDContentTypeTSTInfo,
			EContent:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: eContentRaw},
		},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: m.CertDER},
		SignerInfos:  []CMSSignerInfo{signerInfo},
	}

	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		http.Error(w, "Failed to marshal SignedData", http.StatusInternalServerError)
		return
	}

	contentInfo := CMSContentInfo{
		ContentType: OIDContentTypeSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedDataDER},
	}
	contentInfoDER, err := asn1.Marshal(contentInfo)
	if err != nil {
		http.Error(w, "Failed to marshal ContentInfo", http.StatusInternalServerError)
		return
	}

	resp := TimeStampResp{
		Status:         PKIStatusInfo{Status: 0},
		TimeStampToken: asn1.RawValue{FullBytes: contentInfoDER},
	}

	respDER, err := asn1.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal TimeStampResp", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

func (m *MockTSAServer) respondRejection(w http.ResponseWriter, status int, msg string) {
	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status:       status,
			StatusString: []string{msg},
		},
	}
	der, _ := asn1.Marshal(resp)
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}
