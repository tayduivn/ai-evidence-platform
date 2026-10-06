package pii

import (
	"strings"
	"testing"
)

// TestChallenger_ZeroWidthAndFullWidth_Adversarial probes evasion vectors
// (zero-width spaces, joiners, BOM, soft hyphens, full-width digits, mixed whitespace).
func TestChallenger_ZeroWidthAndFullWidth_Adversarial(t *testing.T) {
	t.Run("CCCD_ZeroWidth_Variations", func(t *testing.T) {
		variations := []struct {
			name  string
			input string
		}{
			{"ZwSpace_BetweenZeros", "0\u200b01090012345"},
			{"ZWNJ_BetweenZeros", "0\u200c01090012345"},
			{"ZWJ_BetweenZeros", "0\u200d01090012345"},
			{"BOM_BetweenZeros", "0\ufeff01090012345"},
			{"SoftHyphen_BetweenZeros", "0\u00ad01090012345"},
			{"AllZeroWidth_Combined", "0\u200b0\u200c1\u200d0\ufeff9\u00ad0012345"},
			{"Leading_ZwSpace", "\u200b001090012345"},
			{"Trailing_BOM", "001090012345\ufeff"},
			{"EveryDigit_Separated", "0\u200b0\u200c1\u200d0\ufeff9\u00ad0\u200b0\u200c1\u200d2\ufeff3\u00ad4\u200b5"},
			{"MultipleConsecutive_Zw", "0\u200b\u200c\u200d\ufeff\u00ad01090012345"},
		}

		for _, tc := range variations {
			t.Run(tc.name, func(t *testing.T) {
				text := "Số CCCD: " + tc.input + " cần xác minh."
				masked, detected := ScanAndMask(text)
				hasCCCD := false
				for _, d := range detected {
					if d == LabelCCCD {
						hasCCCD = true
						break
					}
				}
				if !hasCCCD {
					t.Fatalf("[%s] expected LabelCCCD in detected %v", tc.name, detected)
				}
				if !strings.Contains(masked, "001******345") {
					t.Fatalf("[%s] expected masked CCCD '001******345', got: %s", tc.name, masked)
				}
				if strings.Contains(masked, "001090012345") {
					t.Fatalf("[%s] raw CCCD leaked in masked output: %s", tc.name, masked)
				}
			})
		}
	})

	t.Run("Phone_Domestic_ZeroWidth_Variations", func(t *testing.T) {
		variations := []struct {
			name  string
			input string
		}{
			{"ZwSpace_09", "0\u200b912345678"},
			{"ZWNJ_03", "0\u200c388776655"},
			{"ZWJ_05", "0\u200d588776655"},
			{"BOM_07", "0\ufeff788776655"},
			{"SoftHyphen_08", "0\u00ad888776655"},
			{"AllZeroWidth_09", "0\u200b9\u200c1\u200d2\ufeff3\u00ad4\u200b5\u200c6\u200d7\ufeff8"},
			{"Leading_Zw", "\u200b0912345678"},
			{"Trailing_Zw", "0912345678\u200b"},
			{"MultipleConsecutive_Zw", "0\u200b\u200c\u200d912345678"},
		}

		for _, tc := range variations {
			t.Run(tc.name, func(t *testing.T) {
				text := "Số điện thoại liên hệ: " + tc.input + "."
				masked, detected := ScanAndMask(text)
				hasPhone := false
				for _, d := range detected {
					if d == LabelPhone {
						hasPhone = true
						break
					}
				}
				if !hasPhone {
					t.Fatalf("[%s] expected LabelPhone in detected %v", tc.name, detected)
				}
				if !strings.Contains(masked, "****") {
					t.Fatalf("[%s] expected masked phone with '****', got: %s", tc.name, masked)
				}
				if strings.Contains(masked, "0912345678") {
					t.Fatalf("[%s] raw phone leaked: %s", tc.name, masked)
				}
			})
		}
	})

	t.Run("Phone_International_ZeroWidth_Variations", func(t *testing.T) {
		variations := []struct {
			name  string
			input string
		}{
			{"ZwSpace_AfterPlus", "+\u200b84903112233"},
			{"ZWNJ_Inside84", "+8\u200c4903112233"},
			{"ZWJ_After84", "+84\u200d903112233"},
			{"BOM_InsideLocal", "+849\ufeff03112233"},
			{"SoftHyphen_InsideLocal", "+8490\u00ad3112233"},
			{"EveryDigit_Separated", "+\u200b8\u200c4\u200d9\ufeff0\u00ad3\u200b1\u200c1\u200d2\ufeff2\u00ad3\u200b3"},
		}

		for _, tc := range variations {
			t.Run(tc.name, func(t *testing.T) {
				text := "Hotline: " + tc.input + "."
				masked, detected := ScanAndMask(text)
				hasPhone := false
				for _, d := range detected {
					if d == LabelPhone {
						hasPhone = true
						break
					}
				}
				if !hasPhone {
					t.Fatalf("[%s] expected LabelPhone in detected %v", tc.name, detected)
				}
				if !strings.Contains(masked, "+8490****233") {
					t.Fatalf("[%s] expected masked intl phone '+8490****233', got: %s", tc.name, masked)
				}
				if strings.Contains(masked, "+84903112233") {
					t.Fatalf("[%s] raw intl phone leaked: %s", tc.name, masked)
				}
			})
		}
	})

	t.Run("Bank_Account_ZeroWidth_Variations", func(t *testing.T) {
		variations := []struct {
			name  string
			input string
		}{
			{"Keyword_STK_Zw", "S\u200bT\u200cK:\u200d 19034567890123"},
			{"Keyword_TaiKhoanDiacritics_Zw", "t\u200bài\u200c k\ufeffho\u00adản\u200b: 19034567890123"},
			{"Keyword_TaiKhoanNoDiacritics_Zw", "t\u200bai\u200c k\ufeffho\u00adan\u200b: 19034567890123"},
			{"Keyword_TK_Zw", "T\u200bK:\u200d 0071001234567"},
			{"Digits_ZwSpace", "STK: 1\u200b9034567890123"},
			{"Digits_AllZeroWidth", "STK: 1\u200b9\u200c0\u200d3\ufeff4\u00ad5\u200b6\u200c7\u200d8\ufeff9\u00ad0\u200b1\u200c2\u200d3"},
			{"Both_Keyword_And_Digits", "S\u200bT\u200cK:\u200d 1\ufeff9\u00ad034567890123"},
		}

		for _, tc := range variations {
			t.Run(tc.name, func(t *testing.T) {
				text := "Chuyển tiền vào " + tc.input + " chi nhánh Hà Nội."
				masked, detected := ScanAndMask(text)
				hasBank := false
				for _, d := range detected {
					if d == LabelBankAccount {
						hasBank = true
						break
					}
				}
				if !hasBank {
					t.Fatalf("[%s] expected LabelBankAccount in detected %v", tc.name, detected)
				}
				if !strings.Contains(masked, "******") {
					t.Fatalf("[%s] expected masked bank account with '******', got: %s", tc.name, masked)
				}
			})
		}
	})

	t.Run("FullWidth_Digits_And_Mixed_Whitespace", func(t *testing.T) {
		fullCCCD := "００１０９００１２３４５"
		mixedCCCD := "0０10９001２34５"
		fullPhone := "０９１２３４５６７８"
		fullBank := "１９０３４５６７８９０１２３"

		cases := []struct {
			name         string
			text         string
			expectedType string
			expectedMask string
		}{
			{"All_FullWidth_CCCD", "CCCD " + fullCCCD, LabelCCCD, "001******345"},
			{"Mixed_FullWidth_CCCD", "CCCD " + mixedCCCD, LabelCCCD, "001******345"},
			{"FullWidth_Phone", "SĐT: " + fullPhone, LabelPhone, "091****678"},
			{"FullWidth_Bank", "STK: " + fullBank, LabelBankAccount, "1903******0123"},
			{"NBSP_Whitespace_Bank", "STK:\u00a019034567890123", LabelBankAccount, "1903******0123"},
			{"IdeographicSpace_Bank", "STK:\u3000" + fullBank, LabelBankAccount, "1903******0123"},
			{"EmSpace_CCCD", "CCCD:\u2003" + fullCCCD, LabelCCCD, "001******345"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				masked, detected := ScanAndMask(tc.text)
				found := false
				for _, d := range detected {
					if d == tc.expectedType {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("[%s] expected label %s in %v", tc.name, tc.expectedType, detected)
				}
				if !strings.Contains(masked, tc.expectedMask) {
					t.Fatalf("[%s] expected mask '%s', got: %s", tc.name, tc.expectedMask, masked)
				}
			})
		}
	})

	t.Run("Non_PII_Boundaries_Untouched", func(t *testing.T) {
		safeSamples := []struct {
			name string
			text string
		}{
			{"ISODate_Dash", "Hôm nay là ngày 2026-10-06 cần kiểm tra log."},
			{"ISODate_Slash", "Ngày ký kết: 06/10/2026 trong hợp đồng."},
			{"Date_Dot", "Hạn nộp hồ sơ: 06.10.2026 lúc 17:00."},
			{"CompactDate", "Mã giao dịch: TXN20261006 hoàn tất."},
			{"HTTP_200", "Gateway returned HTTP 200 OK after proxying."},
			{"HTTP_202", "Request accepted with HTTP 202 Accepted status."},
			{"HTTP_404", "Endpoint error status: 404 Not Found."},
			{"HTTP_500", "Server error code 500 Internal Server Error encountered."},
			{"HTTP_403", "AI Registry returned 403 Forbidden for shadow system."},
			{"Money_VND_Dots", "Tổng số tiền vay: 100.000 VND và bảo hiểm 50.000 VND."},
			{"Money_VND_Large", "Số tiền giải ngân là 500.000.000 đ."},
			{"Money_USD_Commas", "Amount transferred: $10,000,000 USD to partner."},
			{"Money_VN_Words", "Khoản vay hạn mức 500 triệu đồng."},
			{"Semver_030", "Platform runtime version v0.3.0 deployed successfully."},
			{"Semver_210", "Model artifact version v2.1.0 loaded."},
			{"Tracking_Alphanumeric", "Tracking ID: ORDER001090012345ABC in transit."},
			{"UUID_String", "Event ID: 018f3a9e-4e89-7b21-9921-3a81289128aa registered."},
			{"HexHash_SHA256", "Artifact hash: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e."},
			{"Metrics_Float", "Latency overhead was 10.198ms with score 745.5."},
			{"NonCCCD_12Digits_Leading1", "Số mã vạch: 123456789012 đã quét thành công."},
			{"TooShort_Phone_9Digits", "Số nội bộ: 012345678 của phòng kế toán."},
			{"Landline_Hanoi", "Số máy bàn cố định: 02438257890 liên hệ trực tiếp."},
			{"ShortNumber_7Digits", "Số phiếu bốc thăm: 1234567 trúng thưởng."},
			{"Standalone_Number_NoKeyword", "Dãy số 19034567890123 không có từ khóa tài khoản."},
		}

		for _, tc := range safeSamples {
			t.Run(tc.name, func(t *testing.T) {
				masked, detected := ScanAndMask(tc.text)
				if len(detected) > 0 {
					t.Fatalf("[%s] false positive detected: %v", tc.name, detected)
				}
				if masked != tc.text {
					t.Fatalf("[%s] text corrupted:\nOriginal: %s\nMasked:   %s", tc.name, tc.text, masked)
				}
			})
		}
	})
}
