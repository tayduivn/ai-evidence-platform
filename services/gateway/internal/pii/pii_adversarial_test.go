package pii

import (
	"strings"
	"testing"
)

// TestAdversarial_CCCD tests adversarial variations and edge cases for CCCD.
func TestAdversarial_CCCD(t *testing.T) {
	t.Run("Valid_CCCD_LeadingZero", func(t *testing.T) {
		inputs := []string{
			"001090012345",
			"079085009876",
			"038192004561",
		}
		for _, in := range inputs {
			masked, detected := ScanAndMask("Số CCCD: " + in)
			if len(detected) == 0 || detected[0] != LabelCCCD {
				t.Errorf("expected CCCD detection for %s, got %v", in, detected)
			}
			if strings.Contains(masked, in) {
				t.Errorf("raw CCCD %s should be masked, got: %s", in, masked)
			}
		}
	})

	t.Run("NonZero_LeadingDigits_12Digits", func(t *testing.T) {
		// By Vietnamese law, CCCD starts with 001-096. A 12-digit number starting with 1-9 is not a CCCD.
		inputs := []string{
			"123456789012",
			"987654321012",
			"555123456789",
		}
		for _, in := range inputs {
			masked, detected := ScanAndMask("Mã số đơn: " + in)
			for _, d := range detected {
				if d == LabelCCCD {
					t.Errorf("12-digit number starting with non-zero %s should NOT be identified as CCCD, detected: %v", in, detected)
				}
			}
			if !strings.Contains(masked, in) {
				t.Errorf("non-CCCD number %s should NOT be masked, got: %s", in, masked)
			}
		}
	})

	t.Run("Boundary_Lengths_11_and_13_digits", func(t *testing.T) {
		short11 := "00109001234"
		long13 := "0010900123456"

		masked11, detected11 := ScanAndMask("Mã hồ sơ: " + short11)
		for _, d := range detected11 {
			if d == LabelCCCD {
				t.Errorf("11 digits %s should not be CCCD, detected: %v", short11, detected11)
			}
		}
		if !strings.Contains(masked11, short11) {
			t.Errorf("11 digits should remain untouched, got: %s", masked11)
		}

		masked13, detected13 := ScanAndMask("Mã vạch: " + long13)
		for _, d := range detected13 {
			if d == LabelCCCD {
				t.Errorf("13 digits %s should not be CCCD, detected: %v", long13, detected13)
			}
		}
		if !strings.Contains(masked13, long13) {
			t.Errorf("13 digits should remain untouched, got: %s", long13)
		}
	})

	t.Run("Alphanumeric_Embedding", func(t *testing.T) {
		in := "ORDER001090012345XYZ"
		masked, detected := ScanAndMask("Tracking: " + in)
		for _, d := range detected {
			if d == LabelCCCD {
				t.Errorf("CCCD inside alphanumeric %s should not be detected, got: %v", in, detected)
			}
		}
		if !strings.Contains(masked, in) {
			t.Errorf("alphanumeric string should remain untouched, got: %s", masked)
		}
	})
}

// TestAdversarial_Phone tests adversarial phone number formats and invalid numbers.
func TestAdversarial_Phone(t *testing.T) {
	t.Run("Invalid_Prefixes", func(t *testing.T) {
		// 012... was old 11-digit mobile prefix; 024... is Hanoi landline
		inputs := []string{
			"0123456789",
			"02431234567",
			"0412345678",
			"02838222333",
		}
		for _, in := range inputs {
			masked, detected := ScanAndMask("Gọi số: " + in)
			for _, d := range detected {
				if d == LabelPhone {
					t.Errorf("invalid mobile prefix %s should not be flagged as mobile PHONE, detected: %v", in, detected)
				}
			}
			if !strings.Contains(masked, in) {
				t.Errorf("invalid mobile number %s should not be masked, got: %s", in, masked)
			}
		}
	})

	t.Run("Alphanumeric_Embedding", func(t *testing.T) {
		in := "ABC0912345678XYZ"
		masked, detected := ScanAndMask("Mã: " + in)
		for _, d := range detected {
			if d == LabelPhone {
				t.Errorf("phone inside alphanumeric %s should not be detected, got: %v", in, detected)
			}
		}
		if !strings.Contains(masked, in) {
			t.Errorf("embedded text should remain untouched, got: %s", masked)
		}
	})

	t.Run("Formatted_Phone_Numbers", func(t *testing.T) {
		// Notice: Formatted phones with delimiters like hyphens, dots, spaces
		tests := []struct {
			raw           string
			description   string
			expectMatched bool
		}{
			{"091-234-5678", "hyphenated domestic", false},
			{"+84.903.112.233", "dotted international", false},
			{"0912.345.678", "dotted domestic", false},
			{"0912 345 678", "spaced domestic", false},
		}

		for _, tc := range tests {
			masked, detected := ScanAndMask("SĐT: " + tc.raw)
			hasPhone := false
			for _, d := range detected {
				if d == LabelPhone {
					hasPhone = true
				}
			}
			t.Logf("[%s] raw=%s -> masked=%s, detected=%v (hasPhone=%v)", tc.description, tc.raw, masked, detected, hasPhone)
		}
	})
}

// TestAdversarial_BankAccount tests exotic keywords, case sensitivity, and boundary lengths.
func TestAdversarial_BankAccount(t *testing.T) {
	t.Run("Exotic_Keywords_And_Casing", func(t *testing.T) {
		tests := []struct {
			input       string
			shouldMatch bool
			desc        string
		}{
			{"STK : 19034567890123", true, "STK with space before colon"},
			{"tk: 19034567890123", true, "lowercase tk with colon"},
			{"TK:19034567890123", true, "TK without space"},
			{"TÀI KHOẢN: 19034567890123", true, "uppercase TÀI KHOẢN"},
			{"tai khoan: 19034567890123", true, "tai khoan without diacritics"},
			{"account: 19034567890123", true, "account with colon"},
			{"account 19034567890123", true, "account with space"},
			{"tai khoan so: 19034567890123", false, "tai khoan so with intervening word 'so'"},
			{"bank account: 19034567890123", true, "bank account keyword"},
		}

		for _, tc := range tests {
			masked, detected := ScanAndMask(tc.input)
			hasBank := false
			for _, d := range detected {
				if d == LabelBankAccount {
					hasBank = true
				}
			}
			if tc.shouldMatch && !hasBank {
				t.Errorf("[%s] Expected BANK_ACCOUNT detection for '%s', got detected=%v", tc.desc, tc.input, detected)
			}
			t.Logf("[%s] '%s' -> masked='%s', detected=%v (matched=%v)", tc.desc, tc.input, masked, detected, hasBank)
		}
	})

	t.Run("Length_Boundaries_7_and_17_digits", func(t *testing.T) {
		short7 := "STK: 1234567"
		masked7, detected7 := ScanAndMask(short7)
		for _, d := range detected7 {
			if d == LabelBankAccount {
				t.Errorf("7-digit account %s should NOT be matched, detected: %v", short7, detected7)
			}
		}
		if !strings.Contains(masked7, "1234567") {
			t.Errorf("7-digit account should not be altered, got: %s", masked7)
		}

		long17 := "STK: 12345678901234567"
		masked17, detected17 := ScanAndMask(long17)
		t.Logf("17-digit account: '%s' -> masked='%s', detected=%v", long17, masked17, detected17)
	})
}

// TestAdversarial_Unicode_Diacritics tests Vietnamese unicode normalization forms (NFC vs NFD).
func TestAdversarial_Unicode_Diacritics(t *testing.T) {
	// NFC: tài khoản (U+00E0 for à, U+1EA3 for ả)
	nfc := "t\u00e0i kho\u1ea3n: 19034567890123"
	// NFD: ta + U+0300 (combining grave) + i + kho + a + U+0309 (combining hook) + n
	nfd := "ta\u0300i kho\u0309an: 19034567890123"

	maskedNFC, detectedNFC := ScanAndMask(nfc)
	maskedNFD, detectedNFD := ScanAndMask(nfd)

	t.Logf("NFC test: '%s' -> masked='%s', detected=%v", nfc, maskedNFC, detectedNFC)
	t.Logf("NFD test: '%s' -> masked='%s', detected=%v", nfd, maskedNFD, detectedNFD)

	hasNFCBank := false
	for _, d := range detectedNFC {
		if d == LabelBankAccount {
			hasNFCBank = true
		}
	}
	if !hasNFCBank {
		t.Errorf("NFC format should match BANK_ACCOUNT")
	}
}
