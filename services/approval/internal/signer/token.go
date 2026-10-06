package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TokenState represents the hardware token session status.
type TokenState string

const (
	TokenStateLoggedOut TokenState = "LOGGED_OUT"
	TokenStateLoggedIn  TokenState = "LOGGED_IN"
	TokenStateLocked    TokenState = "LOCKED"
)

// CAVNTokenConfig holds configuration for the Vietnamese USB PKCS#11 token simulator.
type CAVNTokenConfig struct {
	TokenLabel        string // e.g. "VNPT-CA PKI Token"
	Manufacturer      string // e.g. "VNPT Technology"
	SerialNumber      string // e.g. "VNPT-2026-98124"
	UserPIN           string // default "123456"
	SOPIN             string // default "88888888"
	MaxFailedAttempts int    // default 5
	ApproverName      string // Common Name e.g. "Nguyễn Văn Đắc"
	Organization      string // e.g. "Tổng Công ty Bảo hiểm PTI"
	TaxIDOrCCCD       string // UID identifier e.g. "CCCD:001090012345" or "MST:0101234567"
	PrivateKeyPEM     []byte
	CertificatePEM    []byte
	RootCAPEM         []byte
}

// CAVNTokenSigner simulates a Vietnamese Decree 130/2018 PKCS#11 USB Token.
type CAVNTokenSigner struct {
	mu             sync.Mutex
	config         CAVNTokenConfig
	state          TokenState
	failedAttempts int
	privateKey     *rsa.PrivateKey
	certificate    *x509.Certificate
	certPEM        []byte
	rootCAPEM      []byte
}

// NewCAVNTokenSigner creates a new USB token simulator with Decree 130 X.509 cert attributes.
func NewCAVNTokenSigner(cfg CAVNTokenConfig) (*CAVNTokenSigner, error) {
	if cfg.UserPIN == "" {
		cfg.UserPIN = "123456"
	}
	if cfg.SOPIN == "" {
		cfg.SOPIN = "88888888"
	}
	if cfg.MaxFailedAttempts <= 0 {
		cfg.MaxFailedAttempts = 5
	}
	if cfg.ApproverName == "" {
		cfg.ApproverName = "Người Phê Duyệt CA VN"
	}
	if cfg.Organization == "" {
		cfg.Organization = "Tập đoàn Bưu chính Viễn thông Việt Nam"
	}
	if cfg.TaxIDOrCCCD == "" {
		cfg.TaxIDOrCCCD = "CCCD:001090012345"
	}

	s := &CAVNTokenSigner{
		config:    cfg,
		state:     TokenStateLoggedOut,
		rootCAPEM: cfg.RootCAPEM,
	}

	if len(cfg.PrivateKeyPEM) > 0 && len(cfg.CertificatePEM) > 0 {
		block, _ := pem.Decode(cfg.PrivateKeyPEM)
		if block == nil {
			return nil, errors.New("ca_vn_token: invalid private key PEM")
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err8 != nil {
				return nil, fmt.Errorf("ca_vn_token: parse private key error: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("ca_vn_token: key is not RSA")
			}
			priv = rsaKey
		}
		s.privateKey = priv

		certBlock, _ := pem.Decode(cfg.CertificatePEM)
		if certBlock == nil {
			return nil, errors.New("ca_vn_token: invalid cert PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca_vn_token: parse cert error: %w", err)
		}
		s.certificate = cert
		s.certPEM = cfg.CertificatePEM
	} else {
		// Generate Decree 130 compliant RSA-2048 key and X.509 cert
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("ca_vn_token: RSA key generation failed: %w", err)
		}
		s.privateKey = priv

		// Subject attributes per Decree 130/2018/ND-CP Article 6
		oidUID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1} // userId (UID)
		subject := pkix.Name{
			Country:      []string{"VN"},
			Organization: []string{cfg.Organization},
			CommonName:   cfg.ApproverName,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidUID,
					Value: cfg.TaxIDOrCCCD,
				},
			},
		}

		// Decree 130 / Circular 06 requires Non-Repudiation (ContentCommitment)
		ku := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		certPEM, cert, err := generateX509Cert(priv, subject, ku)
		if err != nil {
			return nil, fmt.Errorf("ca_vn_token: cert generation failed: %w", err)
		}
		s.certificate = cert
		s.certPEM = certPEM
	}

	return s, nil
}

func (s *CAVNTokenSigner) Type() string {
	return "ca_vn_token"
}

// Login performs user PIN verification with lockout counting.
func (s *CAVNTokenSigner) Login(pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == TokenStateLocked {
		return ErrTokenLocked
	}
	if pin != s.config.UserPIN {
		s.failedAttempts++
		if s.failedAttempts >= s.config.MaxFailedAttempts {
			s.state = TokenStateLocked
			return ErrTokenLocked
		}
		return fmt.Errorf("ca_vn_token: invalid PIN (%d/%d attempts remaining)", s.config.MaxFailedAttempts-s.failedAttempts, s.config.MaxFailedAttempts)
	}
	s.failedAttempts = 0
	s.state = TokenStateLoggedIn
	return nil
}

// Unlock resets PIN with Security Officer PIN.
func (s *CAVNTokenSigner) Unlock(soPIN string, newPIN string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if soPIN != s.config.SOPIN {
		return errors.New("ca_vn_token: invalid Security Officer PIN")
	}
	s.config.UserPIN = newPIN
	s.failedAttempts = 0
	s.state = TokenStateLoggedOut
	return nil
}

// Sign signs payload bytes if token is authenticated.
func (s *CAVNTokenSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == TokenStateLocked {
		return nil, nil, ErrTokenLocked
	}
	if s.state == TokenStateLoggedOut {
		// Auto-login with default/configured PIN if available
		if s.config.UserPIN != "" {
			s.state = TokenStateLoggedIn
		} else {
			return nil, nil, ErrPINRequired
		}
	}

	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ca_vn_token: sign error: %w", err)
	}
	return sig, s.certPEM, nil
}

// Verify validates signature and Decree 130 compliance (Country=VN, Non-Repudiation).
func (s *CAVNTokenSigner) Verify(ctx context.Context, payload []byte, signature []byte, certPEM []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, errors.New("ca_vn_token: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("ca_vn_token: parse cert error: %w", err)
	}

	// Validate expiry
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, ErrCertificateExpired
	}

	// Decree 130 Compliance Check: Country must be VN
	hasVN := false
	for _, c := range cert.Subject.Country {
		if c == "VN" {
			hasVN = true
			break
		}
	}
	if !hasVN {
		return false, errors.New("ca_vn_token: non-compliant cert: Subject Country must be VN")
	}

	// Decree 130 Compliance Check: KeyUsage must include Non-Repudiation (ContentCommitment) or DigitalSignature
	if cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return false, errors.New("ca_vn_token: non-compliant cert: missing Non-Repudiation key usage")
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("ca_vn_token: public key is not RSA")
	}

	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature); err != nil {
		return false, ErrInvalidSignature
	}
	return true, nil
}

func (s *CAVNTokenSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	chain := [][]byte{s.certPEM}
	if len(s.rootCAPEM) > 0 {
		chain = append(chain, s.rootCAPEM)
	}
	return chain, nil
}
