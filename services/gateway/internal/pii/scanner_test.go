package pii

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPII_CCCD_DetectionAndMasking(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CCCD 001090012345",
			input:    "Khách hàng mang CCCD 001090012345 yêu cầu mở tài khoản tín dụng.",
			expected: "Khách hàng mang CCCD 001******345 yêu cầu mở tài khoản tín dụng.",
		},
		{
			name:     "CCCD 079085009876",
			input:    "Số định danh: 079085009876 đã được xác thực.",
			expected: "Số định danh: 079******876 đã được xác thực.",
		},
		{
			name:     "CCCD 038192004561",
			input:    "CCCD: 038192004561 hợp lệ.",
			expected: "CCCD: 038******561 hợp lệ.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			masked, detected := ScanAndMask(tc.input)
			if masked != tc.expected {
				t.Fatalf("expected masked:\n%s\ngot:\n%s", tc.expected, masked)
			}
			if len(detected) == 0 || detected[0] != LabelCCCD {
				t.Fatalf("expected detected [%s], got %v", LabelCCCD, detected)
			}
		})
	}
}

func TestPII_CCCD_BoundaryRejections(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "11 digits too short",
			input: "Mã số hồ sơ tham chiếu: 00109001234 (11 số)",
		},
		{
			name:  "13 digits too long",
			input: "Mã vạch sản phẩm: 0010900123456 (13 số)",
		},
		{
			name:  "Embedded in alphanumeric",
			input: "Tracking code: ORDER001090012345ABC in transit",
		},
		{
			name:  "Contains letter",
			input: "Mã kiểm tra 00109001234A không hợp lệ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			masked, detected := ScanAndMask(tc.input)
			if masked != tc.input {
				t.Fatalf("boundary case should not be masked, got: %s", masked)
			}
			for _, d := range detected {
				if d == LabelCCCD {
					t.Fatalf("boundary case should not detect CCCD, got: %v", detected)
				}
			}
		})
	}
}

func TestPII_Phone_DomesticAndInternational(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Domestic 091",
			input:    "Hotline cá nhân: 0912345678, vui lòng gọi.",
			expected: "Hotline cá nhân: 091****678, vui lòng gọi.",
		},
		{
			name:     "Domestic 098",
			input:    "Số điện thoại: 0988776655.",
			expected: "Số điện thoại: 098****655.",
		},
		{
			name:     "International +8490",
			input:    "Liên hệ với số điện thoại +84903112233 để xác minh.",
			expected: "Liên hệ với số điện thoại +8490****233 để xác minh.",
		},
		{
			name:     "Domestic 086",
			input:    "Số Viettel: 0868999888.",
			expected: "Số Viettel: 086****888.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			masked, detected := ScanAndMask(tc.input)
			if masked != tc.expected {
				t.Fatalf("expected:\n%s\ngot:\n%s", tc.expected, masked)
			}
			if len(detected) == 0 || detected[0] != LabelPhone {
				t.Fatalf("expected detected [%s], got %v", LabelPhone, detected)
			}
		})
	}
}

func TestPII_Phone_InvalidPrefixAndTooShort(t *testing.T) {
	tests := []string{
		"Mã định danh cũ: 012345678 không phải SĐT",
		"Số máy lẻ 0912345 quá ngắn",
	}

	for _, input := range tests {
		masked, detected := ScanAndMask(input)
		if masked != input {
			t.Fatalf("expected untouched text, got: %s", masked)
		}
		if len(detected) != 0 {
			t.Fatalf("expected no detection, got: %v", detected)
		}
	}
}

func TestPII_BankAccount_WithContextualKeywords(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "STK Techcombank",
			input:    "Chuyển tiền giải ngân vào STK: 19034567890123 ngân hàng Techcombank.",
			expected: "Chuyển tiền giải ngân vào STK: 1903******0123 ngân hàng Techcombank.",
		},
		{
			name:     "TK Vietcombank",
			input:    "TK: 0071001234567 chi nhánh HCM.",
			expected: "TK: 0071******4567 chi nhánh HCM.",
		},
		{
			name:     "tài khoản VietinBank",
			input:    "tài khoản 101889998888 tại VietinBank.",
			expected: "tài khoản 1018******8888 tại VietinBank.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			masked, detected := ScanAndMask(tc.input)
			if masked != tc.expected {
				t.Fatalf("expected:\n%s\ngot:\n%s", tc.expected, masked)
			}
			if len(detected) == 0 || detected[0] != LabelBankAccount {
				t.Fatalf("expected detected [%s], got %v", LabelBankAccount, detected)
			}
		})
	}
}

func TestPII_MultipleCoexistingEntities(t *testing.T) {
	raw := "Hồ sơ: CCCD 079085009876, SĐT: 0988776655, TK: 0071001234567 VCB."
	masked, detected := ScanAndMask(raw)

	expectedMasked := "Hồ sơ: CCCD 079******876, SĐT: 098****655, TK: 0071******4567 VCB."
	if masked != expectedMasked {
		t.Fatalf("expected masked:\n%s\ngot:\n%s", expectedMasked, masked)
	}

	expectedDetected := []string{"BANK_ACCOUNT", "CCCD", "PHONE"}
	if !reflect.DeepEqual(detected, expectedDetected) {
		t.Fatalf("expected detected %v, got %v", expectedDetected, detected)
	}
}

func TestPII_CleanTextFidelity(t *testing.T) {
	raw := "Chỉ số VN-Index tăng 15 điểm trong phiên giao dịch sáng nay với thanh khoản cao."
	masked, detected := ScanAndMask(raw)

	if masked != raw {
		t.Fatalf("expected raw to equal masked")
	}
	if len(detected) != 0 {
		t.Fatalf("expected 0 detected items, got: %v", detected)
	}
}

func TestPII_EmptyText(t *testing.T) {
	masked, detected := ScanAndMask("")
	if masked != "" {
		t.Fatalf("expected empty string, got: %s", masked)
	}
	if len(detected) != 0 {
		t.Fatalf("expected empty slice, got: %v", detected)
	}
}

func TestPII_MaskMapValues(t *testing.T) {
	input := map[string]interface{}{
		"income": 50000000,
		"note":   "Khách hàng CCCD 001090012345 SĐT 0912345678",
		"details": map[string]interface{}{
			"bank": "STK: 19034567890123",
		},
	}

	maskedMap, labels := MaskMapValues(input)
	expectedLabels := []string{"BANK_ACCOUNT", "CCCD", "PHONE"}
	if !reflect.DeepEqual(labels, expectedLabels) {
		t.Fatalf("expected labels %v, got %v", expectedLabels, labels)
	}

	noteVal := maskedMap["note"].(string)
	if !strings.Contains(noteVal, "001******345") || !strings.Contains(noteVal, "091****678") {
		t.Fatalf("note was not properly masked: %s", noteVal)
	}

	detailsVal := maskedMap["details"].(map[string]interface{})
	bankVal := detailsVal["bank"].(string)
	if !strings.Contains(bankVal, "1903******0123") {
		t.Fatalf("bank was not properly masked: %s", bankVal)
	}
}

func TestPII_MaskMapValues_SlicesAndNil(t *testing.T) {
	// Nil map test
	m, labels := MaskMapValues(nil)
	if m != nil || len(labels) != 0 {
		t.Fatalf("expected nil map and empty labels")
	}

	// Slice inside map test
	input := map[string]interface{}{
		"tags": []interface{}{
			"CCCD 079085009876",
			12345,
			map[string]interface{}{
				"sub": "0988776655",
			},
		},
	}
	m, labels = MaskMapValues(input)
	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %v", labels)
	}
	sliceVal := m["tags"].([]interface{})
	if !strings.Contains(sliceVal[0].(string), "079******876") {
		t.Fatalf("slice item not masked: %v", sliceVal[0])
	}
}

func TestPII_Sanitize_Normalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Zero-width codepoints stripped",
			input:    "0\u200b0\u200c1\u200d0\ufeff9\u00ad0012345",
			expected: "001090012345",
		},
		{
			name:     "Full-width digits converted to ASCII",
			input:    "０１２３４５６７８９",
			expected: "0123456789",
		},
		{
			name:     "Non-standard whitespace normalized",
			input:    "STK:\u00a019034567890123\u3000chi nhánh",
			expected: "STK: 19034567890123 chi nhánh",
		},
		{
			name:     "Preserve normal characters and newlines",
			input:    "Dòng 1\nDòng 2\tDòng 3",
			expected: "Dòng 1\nDòng 2\tDòng 3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitize(tc.input)
			if got != tc.expected {
				t.Fatalf("expected Sanitize(%q) = %q, got %q", tc.input, tc.expected, got)
			}
		})
	}
}

func TestPII_ObfuscatedEntities_DetectionAndMasking(t *testing.T) {
	t.Run("Zero-width space in CCCD", func(t *testing.T) {
		input := "Số CCCD: 0\u200b01090012345 cần xác minh."
		masked, detected := ScanAndMask(input)
		if len(detected) != 1 || detected[0] != LabelCCCD {
			t.Fatalf("expected [%s], got %v", LabelCCCD, detected)
		}
		if !strings.Contains(masked, "001******345") {
			t.Fatalf("expected CCCD masked to 001******345, got: %s", masked)
		}
	})

	t.Run("Full-width unicode digits in CCCD", func(t *testing.T) {
		input := "Khách hàng CCCD ００１０９００１２３４５ mở tài khoản."
		masked, detected := ScanAndMask(input)
		if len(detected) != 1 || detected[0] != LabelCCCD {
			t.Fatalf("expected [%s], got %v", LabelCCCD, detected)
		}
		if !strings.Contains(masked, "001******345") {
			t.Fatalf("expected CCCD masked to 001******345, got: %s", masked)
		}
	})

	t.Run("Zero-width space in Phone", func(t *testing.T) {
		input := "Liên hệ: 0\u200b912345678 để nhận quà."
		masked, detected := ScanAndMask(input)
		if len(detected) != 1 || detected[0] != LabelPhone {
			t.Fatalf("expected [%s], got %v", LabelPhone, detected)
		}
		if !strings.Contains(masked, "091****678") {
			t.Fatalf("expected Phone masked to 091****678, got: %s", masked)
		}
	})

	t.Run("Full-width unicode digits in Phone", func(t *testing.T) {
		input := "Hotline: ０９１２３４５６７８"
		masked, detected := ScanAndMask(input)
		if len(detected) != 1 || detected[0] != LabelPhone {
			t.Fatalf("expected [%s], got %v", LabelPhone, detected)
		}
		if !strings.Contains(masked, "091****678") {
			t.Fatalf("expected Phone masked to 091****678, got: %s", masked)
		}
	})

	t.Run("Zero-width space and full-width in Bank Account", func(t *testing.T) {
		input := "STK: １\u200b９０３４５６７８９０１２３ Techcombank"
		masked, detected := ScanAndMask(input)
		if len(detected) != 1 || detected[0] != LabelBankAccount {
			t.Fatalf("expected [%s], got %v", LabelBankAccount, detected)
		}
		if !strings.Contains(masked, "1903******0123") {
			t.Fatalf("expected Bank Account masked to 1903******0123, got: %s", masked)
		}
	})

	t.Run("Combined obfuscations in single text", func(t *testing.T) {
		input := "Hồ sơ: CCCD ０\u200b０１０９００１２３４５, SĐT 0\u200c988776655, TK: １９\u200d０３４５６７８９０１２３."
		masked, detected := ScanAndMask(input)
		expectedLabels := []string{LabelBankAccount, LabelCCCD, LabelPhone}
		if !reflect.DeepEqual(detected, expectedLabels) {
			t.Fatalf("expected labels %v, got %v", expectedLabels, detected)
		}
		if !strings.Contains(masked, "001******345") || !strings.Contains(masked, "098****655") || !strings.Contains(masked, "1903******0123") {
			t.Fatalf("all entities must be properly masked, got: %s", masked)
		}
	})
}

func BenchmarkPII_50KBPayloadScan(b *testing.B) {
	baseText := "Khách hàng Nguyễn Văn An có CCCD 001090012345 và số điện thoại 0912345678 yêu cầu chuyển vào STK: 19034567890123. "
	// Repeat to reach ~50KB
	repeated := strings.Repeat(baseText, 400) // ~50,000 bytes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, _ = ScanAndMask(repeated)
		dur := time.Since(start)
		if dur > 15*time.Millisecond {
			b.Logf("Warning: 50KB payload took %v (>15ms budget)", dur)
		}
	}
}
