package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_PayloadSingleByteTamper verifies that altering ANY single byte
// across the entire payload causes Verify() to fail for all 3 signers.
func TestAdversarial_PayloadSingleByteTamper(t *testing.T) {
	ctx := context.Background()

	// 1. Setup InternalSigner
	internalSigner, err := NewInternalSigner(InternalSignerConfig{
		ApproverID: "adv-internal-01",
	})
	if err != nil {
		t.Fatalf("failed to init internal signer: %v", err)
	}

	// 2. Setup CAVNTokenSigner
	tokenSigner, err := NewCAVNTokenSigner(CAVNTokenConfig{
		ApproverName: "Nguyễn Văn Đắc",
		UserPIN:      "123456",
	})
	if err != nil {
		t.Fatalf("failed to init token signer: %v", err)
	}

	// 3. Setup CAVNRemoteSigner
	remoteSigner, err := NewCAVNRemoteSigner(CAVNRemoteConfig{
		AuthMode: RemoteAuthAutoApprove,
	})
	if err != nil {
		t.Fatalf("failed to init remote signer: %v", err)
	}
	defer remoteSigner.Close()

	originalPayload := []byte(`{"decision_id":"dec-99882","amount":500000000,"status":"APPROVED","approver":"u-10"}`)

	signers := []struct {
		name   string
		signer Signer
	}{
		{"InternalSigner", internalSigner},
		{"CAVNTokenSigner", tokenSigner},
		{"CAVNRemoteSigner", remoteSigner},
	}

	for _, s := range signers {
		t.Run(s.name, func(t *testing.T) {
			sig, certPEM, err := s.signer.Sign(ctx, originalPayload)
			if err != nil {
				t.Fatalf("%s Sign failed: %v", s.name, err)
			}

			// Clean verify must pass
			ok, err := s.signer.Verify(ctx, originalPayload, sig, certPEM)
			if err != nil || !ok {
				t.Fatalf("%s clean Verify failed: ok=%v, err=%v", s.name, ok, err)
			}

			// Tamper every single byte from index 0 to len-1
			for i := 0; i < len(originalPayload); i++ {
				tampered := make([]byte, len(originalPayload))
				copy(tampered, originalPayload)
				// Flip one bit
				tampered[i] ^= 0x01

				ok, err := s.signer.Verify(ctx, tampered, sig, certPEM)
				if ok || err == nil {
					t.Fatalf("%s failed to detect tamper at byte offset %d ('%c'): ok=%v, err=%v",
						s.name, i, originalPayload[i], ok, err)
				}
				if !errors.Is(err, ErrInvalidSignature) {
					t.Logf("%s returned unexpected error type on tamper: %v", s.name, err)
				}
			}
		})
	}
}

// TestAdversarial_SignatureAndCertTamper verifies that altering signature bytes
// or certificate bytes causes Verify() to reject the signature.
func TestAdversarial_SignatureAndCertTamper(t *testing.T) {
	ctx := context.Background()
	signer, err := NewInternalSigner(InternalSignerConfig{ApproverID: "adv-sig-tamper"})
	if err != nil {
		t.Fatalf("failed to init signer: %v", err)
	}

	payload := []byte(`{"event_id":"018f3a9e","action":"APPROVE"}`)
	sig, certPEM, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 1. Alter first byte of signature
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	ok, err := signer.Verify(ctx, payload, tamperedSig, certPEM)
	if ok || err == nil {
		t.Fatalf("expected error on tampered signature bytes, got ok=%v, err=%v", ok, err)
	}

	// 2. Alter last byte of signature
	copy(tamperedSig, sig)
	tamperedSig[len(sig)-1] ^= 0xAA
	ok, err = signer.Verify(ctx, payload, tamperedSig, certPEM)
	if ok || err == nil {
		t.Fatalf("expected error on tampered signature last byte, got ok=%v, err=%v", ok, err)
	}

	// 3. Truncate signature
	ok, err = signer.Verify(ctx, payload, sig[:len(sig)/2], certPEM)
	if ok || err == nil {
		t.Fatalf("expected error on truncated signature, got ok=%v, err=%v", ok, err)
	}

	// 4. Corrupt cert PEM structure so it fails decoding
	corruptedPEM := []byte("-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!@#$\n-----END CERTIFICATE-----\n")
	ok, err = signer.Verify(ctx, payload, sig, corruptedPEM)
	if ok || err == nil {
		t.Fatalf("expected error on corrupted cert PEM, got ok=%v, err=%v", ok, err)
	}

	// 5. Verify with a DIFFERENT signer's certificate (mismatched public key)
	otherSigner, _ := NewInternalSigner(InternalSignerConfig{ApproverID: "other-signer"})
	otherChain, _ := otherSigner.GetCertificateChain(ctx)
	ok, err = signer.Verify(ctx, payload, sig, otherChain[0])
	if ok || err == nil {
		t.Fatalf("expected error when verifying signature with a different signer's cert, got ok=%v, err=%v", ok, err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature on mismatched cert, got: %v", err)
	}
}

// TestAdversarial_TokenPINLockoutSecurity tests boundary conditions on PIN attempts,
// lock states, SO PIN reset, and Decree 130 regulatory attributes.
func TestAdversarial_TokenPINLockoutSecurity(t *testing.T) {
	ctx := context.Background()
	maxAttempts := 5
	token, err := NewCAVNTokenSigner(CAVNTokenConfig{
		UserPIN:           "654321",
		SOPIN:             "99999999",
		MaxFailedAttempts: maxAttempts,
		ApproverName:      "Nguyễn Văn Đắc",
		Organization:      "PTI Insurance VN",
		TaxIDOrCCCD:       "CCCD:001090012345",
	})
	if err != nil {
		t.Fatalf("NewCAVNTokenSigner failed: %v", err)
	}

	payload := []byte(`{"secure":"token_payload"}`)

	// Attempts 1 to 4: must fail with attempts remaining message, token NOT locked yet
	for i := 1; i < maxAttempts; i++ {
		err := token.Login("wrong_pin")
		if err == nil {
			t.Fatalf("attempt %d: expected error on wrong PIN, got nil", i)
		}
		if errors.Is(err, ErrTokenLocked) {
			t.Fatalf("attempt %d: token locked prematurely", i)
		}
	}

	// Attempt 5: must return ErrTokenLocked and lock the token
	err = token.Login("wrong_pin")
	if !errors.Is(err, ErrTokenLocked) {
		t.Fatalf("attempt 5: expected ErrTokenLocked, got: %v", err)
	}

	// Attempt 6+: must immediately return ErrTokenLocked even if correct PIN is provided!
	err = token.Login("654321")
	if !errors.Is(err, ErrTokenLocked) {
		t.Fatalf("attempt 6 with correct PIN: locked token must reject login, got: %v", err)
	}

	// Sign while locked: must reject
	_, _, err = token.Sign(ctx, payload)
	if !errors.Is(err, ErrTokenLocked) {
		t.Fatalf("Sign while locked must return ErrTokenLocked, got: %v", err)
	}

	// Unlock with WRONG SO PIN: must fail, token remains locked
	err = token.Unlock("wrong_so_pin", "111111")
	if err == nil {
		t.Fatalf("Unlock with wrong SO PIN should fail, got nil")
	}

	// Sign still fails because token is still locked
	_, _, err = token.Sign(ctx, payload)
	if !errors.Is(err, ErrTokenLocked) {
		t.Fatalf("Sign after failed unlock must return ErrTokenLocked, got: %v", err)
	}

	// Unlock with CORRECT SO PIN: resets token to LOGGED_OUT with new PIN
	err = token.Unlock("99999999", "111111")
	if err != nil {
		t.Fatalf("Unlock with correct SO PIN failed: %v", err)
	}

	// Login with OLD PIN: must fail
	err = token.Login("654321")
	if err == nil {
		t.Fatalf("Login with old PIN should fail, got nil")
	}

	// Login with NEW PIN: must succeed
	err = token.Login("111111")
	if err != nil {
		t.Fatalf("Login with new PIN failed: %v", err)
	}

	// Sign now succeeds
	sig, certPEM, err := token.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign after valid unlock failed: %v", err)
	}
	ok, err := token.Verify(ctx, payload, sig, certPEM)
	if err != nil || !ok {
		t.Fatalf("Verify after unlock failed: ok=%v, err=%v", ok, err)
	}
}

// TestAdversarial_Decree130CertificateEnforcement tests that CAVNTokenSigner.Verify
// strictly rejects non-compliant certificates (Country != VN or missing Non-Repudiation).
func TestAdversarial_Decree130CertificateEnforcement(t *testing.T) {
	ctx := context.Background()
	token, _ := NewCAVNTokenSigner(CAVNTokenConfig{UserPIN: "123456"})
	payload := []byte(`{"regulatory":"decree130"}`)

	sig, _, err := token.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// 1. Generate certificate with Country != VN (e.g. US)
	foreignCertPEM := generateCustomTestCert(t, token.privateKey, pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"US Bank"},
		CommonName:   "John Doe",
	}, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, 365*24*time.Hour)

	ok, err := token.Verify(ctx, payload, sig, foreignCertPEM)
	if ok || err == nil {
		t.Fatalf("expected failure for non-VN certificate, got ok=%v, err=%v", ok, err)
	}
	expectedMsg := "Subject Country must be VN"
	if err != nil && !containsStr(err.Error(), expectedMsg) {
		t.Errorf("expected error containing '%s', got: %v", expectedMsg, err)
	}

	// 2. Generate certificate with Country = VN but MISSING Non-Repudiation (ContentCommitment) & DigitalSignature
	noKuCertPEM := generateCustomTestCert(t, token.privateKey, pkix.Name{
		Country:      []string{"VN"},
		Organization: []string{"VN Org"},
		CommonName:   "Nguyen Van A",
	}, x509.KeyUsageKeyEncipherment, 365*24*time.Hour)

	ok, err = token.Verify(ctx, payload, sig, noKuCertPEM)
	if ok || err == nil {
		t.Fatalf("expected failure for missing Non-Repudiation key usage, got ok=%v, err=%v", ok, err)
	}
	expectedKuMsg := "missing Non-Repudiation key usage"
	if err != nil && !containsStr(err.Error(), expectedKuMsg) {
		t.Errorf("expected error containing '%s', got: %v", expectedKuMsg, err)
	}

	// 3. Expired certificate
	expiredCertPEM := generateCustomTestCert(t, token.privateKey, pkix.Name{
		Country:      []string{"VN"},
		Organization: []string{"VN Org"},
		CommonName:   "Nguyen Van A",
	}, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, -24*time.Hour)

	ok, err = token.Verify(ctx, payload, sig, expiredCertPEM)
	if ok || err == nil {
		t.Fatalf("expected failure for expired certificate, got ok=%v, err=%v", ok, err)
	}
	if !errors.Is(err, ErrCertificateExpired) {
		t.Errorf("expected ErrCertificateExpired, got: %v", err)
	}
}

// TestAdversarial_RemoteSignerFailureModes tests error handling across remote failures:
// invalid OTP, invalid OAuth credentials, simulation timeout, context cancellation.
func TestAdversarial_RemoteSignerFailureModes(t *testing.T) {
	ctx := context.Background()

	// 1. Invalid OTP
	remoteOTP, err := NewCAVNRemoteSigner(CAVNRemoteConfig{
		AuthMode: RemoteAuthRequireOTP,
		FixedOTP: "112233",
	})
	if err != nil {
		t.Fatalf("failed to create remote signer: %v", err)
	}
	defer remoteOTP.Close()

	// Alter OTP in caller config
	remoteWrongOTP, _ := NewCAVNRemoteSigner(CAVNRemoteConfig{
		BaseURL:  remoteOTP.config.BaseURL,
		AuthMode: RemoteAuthRequireOTP,
		FixedOTP: "999999", // Wrong OTP
	})
	defer remoteWrongOTP.Close()

	_, _, err = remoteWrongOTP.Sign(ctx, []byte(`{"test":"wrong_otp"}`))
	if !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}

	// 2. Invalid Client Secret / Credentials
	remoteBadAuth, _ := NewCAVNRemoteSigner(CAVNRemoteConfig{
		BaseURL:      remoteOTP.config.BaseURL,
		ClientID:     "ei-approval-service",
		ClientSecret: "WRONG_SECRET",
	})
	defer remoteBadAuth.Close()

	_, _, err = remoteBadAuth.Sign(ctx, []byte(`{"test":"bad_auth"}`))
	if !errors.Is(err, ErrRemoteAuthFailed) {
		t.Fatalf("expected ErrRemoteAuthFailed, got: %v", err)
	}

	// 3. Simulation Timeout
	remoteTimeout, _ := NewCAVNRemoteSigner(CAVNRemoteConfig{
		AuthMode: RemoteAuthSimTimeout,
	})
	defer remoteTimeout.Close()

	_, _, err = remoteTimeout.Sign(ctx, []byte(`{"test":"timeout"}`))
	if !errors.Is(err, ErrRemoteTimeout) {
		t.Fatalf("expected ErrRemoteTimeout, got: %v", err)
	}

	// 4. Pre-canceled Context
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = remoteOTP.Sign(canceledCtx, []byte(`{"test":"canceled"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

// TestAdversarial_HighConcurrencyStress stresses signers under 100 concurrent workers
// to assert thread-safety and absence of race conditions or signature corruption.
func TestAdversarial_HighConcurrencyStress(t *testing.T) {
	ctx := context.Background()
	signer, err := NewInternalSigner(InternalSignerConfig{ApproverID: "stress-tester"})
	if err != nil {
		t.Fatalf("failed to init internal signer: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			payload := []byte(fmt.Sprintf(`{"worker":%d,"action":"APPROVE","ts":%d}`, workerID, time.Now().UnixNano()))
			sig, cert, err := signer.Sign(ctx, payload)
			if err != nil {
				errCh <- fmt.Errorf("worker %d Sign error: %w", workerID, err)
				return
			}
			ok, err := signer.Verify(ctx, payload, sig, cert)
			if err != nil || !ok {
				errCh <- fmt.Errorf("worker %d Verify error: ok=%v, err=%v", workerID, ok, err)
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency stress failure: %v", err)
	}
}

func generateCustomTestCert(t *testing.T, priv *rsa.PrivateKey, subject pkix.Name, keyUsage x509.KeyUsage, validity time.Duration) []byte {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(validity)
	if validity < 0 {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create custom test cert: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || fmt.Sprintf("%s", s) != "" && len(sub) > 0 && containsSub(s, sub))
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
