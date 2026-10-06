package signer

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func findFixturesDir() string {
	// Search upwards for tests/fixtures/certs
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 5; i++ {
		target := filepath.Join(dir, "tests", "fixtures", "certs")
		if _, err := os.Stat(target); err == nil {
			return target
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func TestInternalSigner_DynamicGeneration(t *testing.T) {
	ctx := context.Background()
	s, err := NewInternalSigner(InternalSignerConfig{
		ApproverID:   "lead-approver",
		CommonName:   "Nguyen Van Dac",
		Organization: "Credit Risk Dept",
		Country:      "VN",
	})
	if err != nil {
		t.Fatalf("failed to create InternalSigner: %v", err)
	}

	payload := []byte(`{"decision_id":"dec-001","action":"APPROVE"}`)
	sig, certPEM, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 || len(certPEM) == 0 {
		t.Fatalf("empty signature or cert")
	}

	ok, err := s.Verify(ctx, payload, sig, certPEM)
	if err != nil || !ok {
		t.Fatalf("Verify failed: ok=%v, err=%v", ok, err)
	}

	// Tampered payload must fail
	tampered := []byte(`{"decision_id":"dec-001","action":"REJECT"}`)
	ok, err = s.Verify(ctx, tampered, sig, certPEM)
	if ok || err == nil {
		t.Fatalf("Verify should fail for tampered payload, got ok=%v, err=%v", ok, err)
	}

	// Cert chain
	chain, err := s.GetCertificateChain(ctx)
	if err != nil || len(chain) == 0 {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
}

func TestInternalSigner_WithFixtureCerts(t *testing.T) {
	fixtureDir := findFixturesDir()
	if fixtureDir == "" {
		t.Skip("fixture certs directory not found")
	}

	keyPEM, err := os.ReadFile(filepath.Join(fixtureDir, "signer_1.key"))
	if err != nil {
		t.Fatalf("read signer_1.key failed: %v", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(fixtureDir, "signer_1.pem"))
	if err != nil {
		t.Fatalf("read signer_1.pem failed: %v", err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(fixtureDir, "root_ca.pem"))
	if err != nil {
		t.Fatalf("read root_ca.pem failed: %v", err)
	}

	ctx := context.Background()
	s, err := NewInternalSigner(InternalSignerConfig{
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
		RootCAPEM:      rootPEM,
	})
	if err != nil {
		t.Fatalf("failed to create signer with fixtures: %v", err)
	}

	payload := []byte(`{"decision_id":"dec-fix-1","amount":500000000}`)
	sig, pemOut, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	ok, err := s.Verify(ctx, payload, sig, pemOut)
	if err != nil || !ok {
		t.Fatalf("Verify failed: ok=%v, err=%v", ok, err)
	}
}

func TestCAVNTokenSigner_PINWorkflowAndLockout(t *testing.T) {
	ctx := context.Background()
	s, err := NewCAVNTokenSigner(CAVNTokenConfig{
		UserPIN:           "123456",
		SOPIN:             "88888888",
		MaxFailedAttempts: 5,
		ApproverName:      "Nguyen Van Dac",
		Organization:      "PTI Insurance",
		TaxIDOrCCCD:       "CCCD:001090012345",
	})
	if err != nil {
		t.Fatalf("failed to create token signer: %v", err)
	}

	// 1. Invalid PIN submissions up to lockout
	for i := 1; i <= 4; i++ {
		err := s.Login("wrong")
		if err == nil {
			t.Fatalf("expected error on wrong PIN, got nil")
		}
	}

	// 5th failed attempt should lock token
	err = s.Login("wrong")
	if err != ErrTokenLocked {
		t.Fatalf("expected ErrTokenLocked, got: %v", err)
	}

	// Signing while locked must fail
	payload := []byte(`{"test":"lockout"}`)
	_, _, err = s.Sign(ctx, payload)
	if err != ErrTokenLocked {
		t.Fatalf("expected ErrTokenLocked on Sign, got: %v", err)
	}

	// Unlock with SO PIN
	err = s.Unlock("88888888", "654321")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Login with new PIN
	err = s.Login("654321")
	if err != nil {
		t.Fatalf("Login with new PIN failed: %v", err)
	}

	// Sign successfully
	sig, certPEM, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign failed after unlock: %v", err)
	}

	ok, err := s.Verify(ctx, payload, sig, certPEM)
	if err != nil || !ok {
		t.Fatalf("Verify token cert failed: ok=%v, err=%v", ok, err)
	}
}

func TestCAVNRemoteSigner_AutoApproveAndOTP(t *testing.T) {
	ctx := context.Background()
	s, err := NewCAVNRemoteSigner(CAVNRemoteConfig{
		AuthMode: RemoteAuthRequireOTP,
		FixedOTP: "998877",
	})
	if err != nil {
		t.Fatalf("failed to create remote signer: %v", err)
	}
	defer s.Close()

	payload := []byte(`{"remote":"test_payload"}`)
	sig, certPEM, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign with OTP failed: %v", err)
	}

	ok, err := s.Verify(ctx, payload, sig, certPEM)
	if err != nil || !ok {
		t.Fatalf("Verify remote signature failed: ok=%v, err=%v", ok, err)
	}

	// Test invalid OTP mode
	sBad, err := NewCAVNRemoteSigner(CAVNRemoteConfig{
		AuthMode: RemoteAuthRequireOTP,
		FixedOTP: "000000",
		BaseURL:  s.config.BaseURL, // Point to the same mock server expecting 998877
	})
	if err != nil {
		t.Fatalf("failed to create sBad: %v", err)
	}
	defer sBad.Close()

	_, _, err = sBad.Sign(ctx, payload)
	if err != ErrInvalidOTP {
		t.Fatalf("expected ErrInvalidOTP, got: %v", err)
	}
}

func TestSignerRegistry_PolymorphicDispatch(t *testing.T) {
	registry := NewRegistry()

	internal, _ := NewInternalSigner(InternalSignerConfig{ApproverID: "u1"})
	token, _ := NewCAVNTokenSigner(CAVNTokenConfig{ApproverName: "u2"})
	remote, _ := NewCAVNRemoteSigner(CAVNRemoteConfig{AuthMode: RemoteAuthAutoApprove})
	defer remote.Close()

	registry.Register(internal)
	registry.Register(token)
	registry.Register(remote)

	list := registry.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 signers, got %d", len(list))
	}

	ctx := context.Background()
	payload := []byte(`{"concurrent":"registry_test"}`)

	var wg sync.WaitGroup
	for _, st := range []string{"internal", "ca_vn_token", "ca_vn_remote"} {
		for i := 0; i < 5; i++ {
			wg.Add(1)
			signerType := st
			go func() {
				defer wg.Done()
				s, err := registry.Get(signerType)
				if err != nil {
					t.Errorf("Get signer %s error: %v", signerType, err)
					return
				}
				sig, cert, err := s.Sign(ctx, payload)
				if err != nil {
					t.Errorf("Signer %s Sign error: %v", signerType, err)
					return
				}
				ok, err := s.Verify(ctx, payload, sig, cert)
				if err != nil || !ok {
					t.Errorf("Signer %s Verify error: ok=%v, err=%v", signerType, ok, err)
				}
			}()
		}
	}
	wg.Wait()
}
