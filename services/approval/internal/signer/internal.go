package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// InternalSignerConfig holds configuration for InternalSigner.
type InternalSignerConfig struct {
	ApproverID     string
	CommonName     string
	Organization   string
	Country        string
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	RootCAPEM      []byte
	KeySizeBits    int // default 2048
}

// InternalSigner implements RSA-2048 PKCS#1 v1.5 / SHA-256 signing for internal SSO/RBAC.
type InternalSigner struct {
	mu          sync.RWMutex
	config      InternalSignerConfig
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	certPEM     []byte
	rootCAPEM   []byte
}

// NewInternalSigner initializes an InternalSigner with optional existing key/cert or dynamic generation.
func NewInternalSigner(cfg InternalSignerConfig) (*InternalSigner, error) {
	s := &InternalSigner{
		config:    cfg,
		rootCAPEM: cfg.RootCAPEM,
	}

	if len(cfg.PrivateKeyPEM) > 0 && len(cfg.CertificatePEM) > 0 {
		// Load provided key
		block, _ := pem.Decode(cfg.PrivateKeyPEM)
		if block == nil {
			return nil, errors.New("internal_signer: invalid private key PEM")
		}
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS#8
			key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err8 != nil {
				return nil, fmt.Errorf("internal_signer: failed to parse private key: %w (pkcs8: %v)", err, err8)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("internal_signer: private key is not RSA")
			}
			privKey = rsaKey
		}
		s.privateKey = privKey

		// Load provided cert
		certBlock, _ := pem.Decode(cfg.CertificatePEM)
		if certBlock == nil {
			return nil, errors.New("internal_signer: invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("internal_signer: failed to parse certificate: %w", err)
		}
		s.certificate = cert
		s.certPEM = cfg.CertificatePEM
	} else {
		// Generate dynamic RSA key and self-signed certificate
		keySize := cfg.KeySizeBits
		if keySize <= 0 {
			keySize = 2048
		}
		priv, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, fmt.Errorf("internal_signer: failed to generate RSA key: %w", err)
		}
		s.privateKey = priv

		cn := cfg.CommonName
		if cn == "" {
			cn = cfg.ApproverID
			if cn == "" {
				cn = "Internal System Signer"
			}
		}
		org := cfg.Organization
		if org == "" {
			org = "Enterprise Audit Department"
		}
		country := cfg.Country
		if country == "" {
			country = "VN"
		}

		subject := pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		}

		certPEM, cert, err := generateX509Cert(priv, subject, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
		if err != nil {
			return nil, fmt.Errorf("internal_signer: failed to generate cert: %w", err)
		}
		s.certificate = cert
		s.certPEM = certPEM
	}

	return s, nil
}

func (s *InternalSigner) Type() string {
	return "internal"
}

func (s *InternalSigner) Sign(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("internal_signer: signing error: %w", err)
	}
	return sig, s.certPEM, nil
}

func (s *InternalSigner) Verify(ctx context.Context, payload []byte, signature []byte, certPEM []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, errors.New("internal_signer: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("internal_signer: invalid certificate: %w", err)
	}

	// Validate expiry
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, ErrCertificateExpired
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("internal_signer: certificate public key is not RSA")
	}

	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature); err != nil {
		return false, ErrInvalidSignature
	}
	return true, nil
}

func (s *InternalSigner) GetCertificateChain(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	chain := [][]byte{s.certPEM}
	if len(s.rootCAPEM) > 0 {
		chain = append(chain, s.rootCAPEM)
	}
	return chain, nil
}

func generateX509Cert(priv *rsa.PrivateKey, subject pkix.Name, keyUsage x509.KeyUsage) ([]byte, *x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	cert, err := x509.ParseCertificate(derBytes)
	return certPEM, cert, err
}
