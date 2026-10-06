package ledger

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Standard OIDs defined in RFC 3161, RFC 5652, and RFC 5280.
var (
	OIDSHA256                  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDContentTypeSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentTypeTSTInfo      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	OIDPolicyDefaultMockTSA    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	OIDSignatureSha256WithRSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// AlgorithmIdentifier represents an ASN.1 algorithm identifier structure.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MessageImprint contains the hash algorithm and digest of the datum to be timestamped.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampReq represents an RFC 3161 timestamp query.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []asn1.RawValue       `asn1:"optional,tag:0"`
}

// PKIStatusInfo encodes status codes returned by a TSA.
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// TimeStampResp represents an RFC 3161 timestamp reply.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"` // CMS ContentInfo DER bytes
}

// Accuracy specifies the time accuracy of the TSA clock.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// TSTInfo represents the signed timestamp payload inside CMS SignedData.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time       `asn1:"generalized"`
	Accuracy       Accuracy        `asn1:"optional"`
	Ordering       bool            `asn1:"optional,default:false"`
	Nonce          *big.Int        `asn1:"optional"`
	TSA            asn1.RawValue   `asn1:"optional,tag:0"`
	Extensions     []asn1.RawValue `asn1:"optional,tag:1"`
}

// CMSContentInfo represents the outermost CMS (RFC 5652) wrapper.
type CMSContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// CMSSignedData represents CMS SignedData payload.
type CMSSignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo CMSEncapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []CMSSignerInfo `asn1:"set"`
}

// CMSEncapContentInfo wraps encapsulated content (TSTInfo).
type CMSEncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// CMSSignerInfo contains the signature from the TSA.
type CMSSignerInfo struct {
	Version            int
	SID                CMSIssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// CMSIssuerAndSerialNumber identifies the certificate of the signer.
type CMSIssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// CreateTimeStampReq constructs an RFC 3161 DER-encoded TimeStampReq for a given Root Hash.
func CreateTimeStampReq(rootHash []byte, policyOID asn1.ObjectIdentifier) ([]byte, *big.Int, error) {
	if len(rootHash) == 0 {
		return nil, nil, errors.New("root hash cannot be empty")
	}

	h := sha256.Sum256(rootHash)

	nonceBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	nonce := new(big.Int).SetBytes(nonceBytes)

	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  OIDSHA256,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: h[:],
		},
		ReqPolicy: policyOID,
		Nonce:     nonce,
		CertReq:   true,
	}

	derBytes, err := asn1.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal TimeStampReq: %w", err)
	}

	return derBytes, nonce, nil
}

// TSAClientConfig defines connection options for external TSA queries.
type TSAClientConfig struct {
	PrimaryURL    string
	SecondaryURL  string
	HTTPTimeout   time.Duration
	MaxRetries    int
	PolicyOID     asn1.ObjectIdentifier
	TrustedRootCA *x509.CertPool
}

// RFC3161Client manages timestamp requests and cryptographic verification.
type RFC3161Client struct {
	config     TSAClientConfig
	httpClient *http.Client
}

// NewRFC3161Client creates an initialized RFC 3161 client.
func NewRFC3161Client(cfg TSAClientConfig) *RFC3161Client {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	return &RFC3161Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
	}
}

// RequestTimestamp sends TimeStampReq to TSA endpoints and returns raw reply DER, parsed TSTInfo, and TSA cert.
func (c *RFC3161Client) RequestTimestamp(ctx context.Context, rootHash []byte) ([]byte, *TSTInfo, *x509.Certificate, error) {
	reqDER, nonce, err := CreateTimeStampReq(rootHash, c.config.PolicyOID)
	if err != nil {
		return nil, nil, nil, err
	}

	urls := []string{c.config.PrimaryURL}
	if c.config.SecondaryURL != "" {
		urls = append(urls, c.config.SecondaryURL)
	}

	var lastErr error
	for _, targetURL := range urls {
		if targetURL == "" {
			continue
		}
		for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
			respDER, err := c.postTimestampQuery(ctx, targetURL, reqDER)
			if err != nil {
				lastErr = err
				time.Sleep(time.Duration(1<<attempt) * 100 * time.Millisecond)
				continue
			}

			tstInfo, tsaCert, valErr := c.ValidateResponse(respDER, rootHash, nonce)
			if valErr != nil {
				lastErr = valErr
				break // Cryptographic validation error, do not retry same bad payload
			}

			return respDER, tstInfo, tsaCert, nil
		}
	}

	return nil, nil, nil, fmt.Errorf("all TSA endpoints failed: %w", lastErr)
}

func (c *RFC3161Client) postTimestampQuery(ctx context.Context, tsaURL string, reqDER []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP post failed to %s: %w", tsaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSA returned HTTP %d", resp.StatusCode)
	}

	respDER, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read TSA response: %w", err)
	}

	return respDER, nil
}

// ValidateResponse parses and cryptographically validates a TimeStampResp against expected root hash and nonce.
func (c *RFC3161Client) ValidateResponse(respDER []byte, rootHash []byte, expectedNonce *big.Int) (*TSTInfo, *x509.Certificate, error) {
	var tsResp TimeStampResp
	_, err := asn1.Unmarshal(respDER, &tsResp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal TimeStampResp: %w", err)
	}

	// 1. Check PKIStatus
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		statusStr := fmt.Sprintf("status=%d", tsResp.Status.Status)
		if len(tsResp.Status.StatusString) > 0 {
			statusStr += fmt.Sprintf(" msg=%v", tsResp.Status.StatusString)
		}
		return nil, nil, fmt.Errorf("TSA rejected request: %s", statusStr)
	}

	if len(tsResp.TimeStampToken.Bytes) == 0 && len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, nil, errors.New("TimeStampResp missing TimeStampToken")
	}

	tokenBytes := tsResp.TimeStampToken.FullBytes
	if len(tokenBytes) == 0 {
		tokenBytes = tsResp.TimeStampToken.Bytes
	}

	// 2. Unmarshal CMS ContentInfo
	var contentInfo CMSContentInfo
	if _, err := asn1.Unmarshal(tokenBytes, &contentInfo); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal CMS ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDContentTypeSignedData) {
		return nil, nil, fmt.Errorf("expected SignedData content type, got %s", contentInfo.ContentType)
	}

	// 3. Unmarshal CMS SignedData
	var signedData CMSSignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal SignedData: %w", err)
	}

	if !signedData.EncapContentInfo.EContentType.Equal(OIDContentTypeTSTInfo) {
		return nil, nil, fmt.Errorf("expected TSTInfo eContentType, got %s", signedData.EncapContentInfo.EContentType)
	}

	// 4. Unmarshal TSTInfo from eContent
	var tstInfo TSTInfo
	var rawOCTET []byte
	var tstBytes []byte

	// eContent is an [0] EXPLICIT OCTET STRING containing DER of TSTInfo
	if _, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &rawOCTET); err == nil {
		tstBytes = rawOCTET
		if _, err := asn1.Unmarshal(rawOCTET, &tstInfo); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal inner TSTInfo: %w", err)
		}
	} else {
		// Fallback: direct TSTInfo bytes
		tstBytes = signedData.EncapContentInfo.EContent.Bytes
		if _, errFallback := asn1.Unmarshal(tstBytes, &tstInfo); errFallback != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal TSTInfo: %w", errFallback)
		}
	}

	// 5. Verify Nonce
	if expectedNonce != nil {
		if tstInfo.Nonce == nil || expectedNonce.Cmp(tstInfo.Nonce) != 0 {
			return nil, nil, fmt.Errorf("nonce mismatch: expected %v, got %v", expectedNonce, tstInfo.Nonce)
		}
	}

	// 6. Verify MessageImprint matches SHA256(rootHash)
	expectedHash := sha256.Sum256(rootHash)
	if !tstInfo.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		return nil, nil, fmt.Errorf("unexpected hash algorithm in TSTInfo: %s", tstInfo.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, expectedHash[:]) {
		return nil, nil, errors.New("hashed message in TSTInfo does not match SHA256(rootHash)")
	}

	// 7. Extract TSA Certificate and enforce presence
	if len(signedData.Certificates.Bytes) == 0 {
		return nil, nil, errors.New("CMS SignedData missing TSA certificates")
	}

	certs, parseErr := x509.ParseCertificates(signedData.Certificates.Bytes)
	if parseErr != nil || len(certs) == 0 {
		return nil, nil, fmt.Errorf("failed to parse TSA certificates: %w", parseErr)
	}
	tsaCert := certs[0]

	// Enforce id-kp-timeStamping extended key usage
	hasTSAEKU := false
	for _, eku := range tsaCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTSAEKU = true
			break
		}
	}
	for _, o := range tsaCert.UnknownExtKeyUsage {
		if o.Equal(OIDExtKeyUsageTimeStamping) {
			hasTSAEKU = true
			break
		}
	}
	if !hasTSAEKU {
		return nil, nil, errors.New("TSA signing certificate missing required id-kp-timeStamping extended key usage")
	}

	// 8. Validate TSA Certificate against TrustedRootCA (if configured)
	if c.config.TrustedRootCA != nil {
		verifyOpts := x509.VerifyOptions{
			Roots:       c.config.TrustedRootCA,
			CurrentTime: tstInfo.GenTime,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}
		if len(certs) > 1 {
			intermediates := x509.NewCertPool()
			for _, intermediate := range certs[1:] {
				intermediates.AddCert(intermediate)
			}
			verifyOpts.Intermediates = intermediates
		}
		if _, err := tsaCert.Verify(verifyOpts); err != nil {
			return nil, nil, fmt.Errorf("TSA certificate chain verification failed: %w", err)
		}
	}

	// 9. Unconditionally verify RSA Signature
	if len(signedData.SignerInfos) == 0 {
		return nil, nil, errors.New("CMS SignedData missing SignerInfo")
	}
	signerInfo := signedData.SignerInfos[0]

	rsaPub, ok := tsaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("unsupported TSA public key type; expected RSA")
	}

	var dataToVerify []byte
	if len(signerInfo.SignedAttrs.Bytes) > 0 || len(signerInfo.SignedAttrs.FullBytes) > 0 {
		// RFC 5652 Section 5.4: If signedAttrs are present, signature is computed over
		// the DER encoding of SignedAttrs with tag changed to SET OF (0x31)
		rawAttrs := signerInfo.SignedAttrs.FullBytes
		if len(rawAttrs) == 0 {
			rawAttrs = signerInfo.SignedAttrs.Bytes
		}
		setAttrs := make([]byte, len(rawAttrs))
		copy(setAttrs, rawAttrs)
		if len(setAttrs) > 0 && setAttrs[0] == 0xA0 {
			setAttrs[0] = 0x31 // change tag [0] to SET OF 0x31
		}
		attrDigest := sha256.Sum256(setAttrs)
		dataToVerify = attrDigest[:]
	} else {
		// Direct signature over encapsulated TSTInfo DER bytes
		tstDigest := sha256.Sum256(tstBytes)
		dataToVerify = tstDigest[:]
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, dataToVerify, signerInfo.Signature); err != nil {
		return nil, nil, fmt.Errorf("cryptographic signature verification failed: %w", err)
	}

	return &tstInfo, tsaCert, nil
}
