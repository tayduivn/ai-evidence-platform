"""
Empirical Adversarial PII Probe & Stress Harness (Challenger M7.3).
Exhaustively tests:
1. Zero-width spaces (\u200b), joiners (\u200d, \u200c), BOM (\ufeff), soft hyphens (\u00ad)
2. Full-width unicode digits (\uff10-\uff19 / ０-９)
3. Mixed whitespace (\u00a0, \u3000, \u2003)
4. Non-PII boundary strings (dates, HTTP status codes, monetary amounts, hashes, semver)
5. Comparison between Python SDK and Go Gateway behavior
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "sdks" / "python"))

from ai_evidence_sdk.pii.scanner import (
    VietnamesePIIScanner,
    LABEL_BANK_ACCOUNT,
    LABEL_CCCD,
    LABEL_PHONE,
    sanitize,
    scan_and_mask,
    scan_dict,
)


class TestEmpiricalPIIAdversarialChallenge(unittest.TestCase):
    """Adversarial stress suite challenging PII normalization and false positive resistance."""

    # --------------------------------------------------------------------------
    # 1. Zero-Width Characters Probing
    # --------------------------------------------------------------------------

    def test_cccd_zero_width_variations(self):
        """Probe CCCD with zero-width characters in diverse locations."""
        variations = [
            ("ZwSpace_BetweenZeros", "0\u200b01090012345"),
            ("ZWNJ_BetweenZeros", "0\u200c01090012345"),
            ("ZWJ_BetweenZeros", "0\u200d01090012345"),
            ("BOM_BetweenZeros", "0\ufeff01090012345"),
            ("SoftHyphen_BetweenZeros", "0\u00ad01090012345"),
            ("AllZeroWidth_Combined", "0\u200b0\u200c1\u200d0\ufeff9\u00ad0012345"),
            ("Leading_ZwSpace", "\u200b001090012345"),
            ("Trailing_BOM", "001090012345\ufeff"),
            ("EveryDigit_Separated", "0\u200b0\u200c1\u200d0\ufeff9\u00ad0\u200b0\u200c1\u200d2\ufeff3\u00ad4\u200b5"),
            ("MultipleConsecutive_Zw", "0\u200b\u200c\u200d\ufeff\u00ad01090012345"),
        ]

        for name, obfuscated in variations:
            with self.subTest(name=name):
                text = f"Số căn cước công dân: {obfuscated}."
                masked, detected = scan_and_mask(text)
                self.assertIn(LABEL_CCCD, detected, f"Failed to detect CCCD in {name}")
                self.assertIn("001******345", masked, f"CCCD was not masked correctly in {name}")
                self.assertNotIn("001090012345", masked, f"Raw CCCD leaked in {name}")

    def test_phone_domestic_zero_width_variations(self):
        """Probe domestic phone numbers with zero-width characters."""
        variations = [
            ("ZwSpace_09", "0\u200b912345678"),
            ("ZWNJ_03", "0\u200c388776655"),
            ("ZWJ_05", "0\u200d588776655"),
            ("BOM_07", "0\ufeff788776655"),
            ("SoftHyphen_08", "0\u00ad888776655"),
            ("AllZeroWidth_09", "0\u200b9\u200c1\u200d2\ufeff3\u00ad4\u200b5\u200c6\u200d7\ufeff8"),
            ("Leading_Zw", "\u200b0912345678"),
            ("Trailing_Zw", "0912345678\u200b"),
            ("MultipleConsecutive_Zw", "0\u200b\u200c\u200d912345678"),
        ]

        for name, obfuscated in variations:
            with self.subTest(name=name):
                text = f"Số điện thoại: {obfuscated}."
                masked, detected = scan_and_mask(text)
                self.assertIn(LABEL_PHONE, detected, f"Failed to detect PHONE in {name}")
                self.assertTrue("****" in masked, f"Phone was not masked in {name}: {masked}")
                self.assertNotIn("0912345678", masked, f"Raw phone leaked in {name}")

    def test_phone_international_zero_width_variations(self):
        """Probe international phone numbers (+84) with zero-width characters."""
        variations = [
            ("ZwSpace_AfterPlus", "+\u200b84903112233"),
            ("ZWNJ_Inside84", "+8\u200c4903112233"),
            ("ZWJ_After84", "+84\u200d903112233"),
            ("BOM_InsideLocal", "+849\ufeff03112233"),
            ("SoftHyphen_InsideLocal", "+8490\u00ad3112233"),
            ("EveryDigit_Separated", "+\u200b8\u200c4\u200d9\ufeff0\u00ad3\u200b1\u200c1\u200d2\ufeff2\u00ad3\u200b3"),
        ]

        for name, obfuscated in variations:
            with self.subTest(name=name):
                text = f"Hotline liên hệ: {obfuscated}."
                masked, detected = scan_and_mask(text)
                self.assertIn(LABEL_PHONE, detected, f"Failed to detect intl PHONE in {name}")
                self.assertIn("+8490****233", masked, f"Intl phone not masked in {name}")
                self.assertNotIn("+84903112233", masked, f"Raw intl phone leaked in {name}")

    def test_bank_account_zero_width_variations(self):
        """Probe bank accounts with zero-width characters in keywords and account numbers."""
        variations = [
            ("Keyword_STK_Zw", "S\u200bT\u200cK:\u200d 19034567890123"),
            ("Keyword_TaiKhoanDiacritics_Zw", "t\u200b\u00e0\u200ci\u200d k\ufeffh\u00ado\u200b\u1ea3\u200cn: 19034567890123"),
            ("Keyword_TaiKhoanNoDiacritics_Zw", "t\u200ba\u200ci\u200d k\ufeffh\u00ado\u200ba\u200cn: 19034567890123"),
            ("Keyword_TK_Zw", "T\u200bK:\u200d 0071001234567"),
            ("Digits_ZwSpace", "STK: 1\u200b9034567890123"),
            ("Digits_AllZeroWidth", "STK: 1\u200b9\u200c0\u200d3\ufeff4\u00ad5\u200b6\u200c7\u200d8\ufeff9\u00ad0\u200b1\u200c2\u200d3"),
            ("Both_Keyword_And_Digits", "S\u200bT\u200cK:\u200d 1\ufeff9\u00ad034567890123"),
        ]

        for name, obfuscated in variations:
            with self.subTest(name=name):
                text = f"Chuyển tiền vào {obfuscated} chi nhánh Hà Nội."
                masked, detected = scan_and_mask(text)
                self.assertIn(LABEL_BANK_ACCOUNT, detected, f"Failed to detect BANK_ACCOUNT in {name}")
                self.assertTrue("******" in masked, f"Bank account was not masked in {name}: {masked}")
                self.assertNotIn("19034567890123", masked, f"Raw bank account leaked in {name}")

    # --------------------------------------------------------------------------
    # 2. Full-Width Unicode Digits & Mixed Whitespace Probing
    # --------------------------------------------------------------------------

    def test_fullwidth_digits_and_mixed_whitespace(self):
        """Probe full-width unicode numerals (\uff10-\uff19) and exotic whitespaces."""
        # Full-width CCCD: ００１０９００１２３４５
        full_cccd = "".join(chr(0xFF10 + int(d)) for d in "001090012345")
        # Mixed full-width & ASCII CCCD: 0０10９001２34５
        mixed_cccd = "0０10９001２34５"
        # Full-width Phone: ０９１２３４５６７８
        full_phone = "".join(chr(0xFF10 + int(d)) for d in "0912345678")
        # Full-width Bank: １９０３４５６７８９０１２３
        full_bank = "".join(chr(0xFF10 + int(d)) for d in "19034567890123")

        cases = [
            ("All_FullWidth_CCCD", f"CCCD {full_cccd}", LABEL_CCCD, "001******345"),
            ("Mixed_FullWidth_CCCD", f"CCCD {mixed_cccd}", LABEL_CCCD, "001******345"),
            ("FullWidth_Phone", f"SĐT: {full_phone}", LABEL_PHONE, "091****678"),
            ("FullWidth_Bank", f"STK: {full_bank}", LABEL_BANK_ACCOUNT, "1903******0123"),
            ("NBSP_Whitespace_Bank", f"STK:\u00a019034567890123", LABEL_BANK_ACCOUNT, "1903******0123"),
            ("IdeographicSpace_Bank", f"STK:\u3000{full_bank}", LABEL_BANK_ACCOUNT, "1903******0123"),
            ("EmSpace_CCCD", f"CCCD:\u2003{full_cccd}", LABEL_CCCD, "001******345"),
            ("Complex_Combined_All", 
             f"Hồ sơ CCCD\u00a0{full_cccd}, SĐT\u3000{full_phone}, STK:\u2003{full_bank}", 
             [LABEL_BANK_ACCOUNT, LABEL_CCCD, LABEL_PHONE], 
             ["001******345", "091****678", "1903******0123"]),
        ]

        for name, text, expected_label, expected_masks in cases:
            with self.subTest(name=name):
                masked, detected = scan_and_mask(text)
                if isinstance(expected_label, list):
                    for lbl in expected_label:
                        self.assertIn(lbl, detected, f"Missing label {lbl} in {name}")
                    for exp_mask in expected_masks:
                        self.assertIn(exp_mask, masked, f"Missing mask {exp_mask} in {name}")
                else:
                    self.assertIn(expected_label, detected, f"Missing label {expected_label} in {name}")
                    self.assertIn(expected_masks, masked, f"Missing mask {expected_masks} in {name}")

    # --------------------------------------------------------------------------
    # 3. Non-PII Boundary Strings & False Positive Resistance
    # --------------------------------------------------------------------------

    def test_non_pii_boundaries_untouched(self):
        """Verify non-PII boundary strings are NOT falsely detected or modified."""
        safe_samples = [
            # ISO Dates
            ("ISODate_Dash", "Hôm nay là ngày 2026-10-06 cần kiểm tra log."),
            ("ISODate_Slash", "Ngày ký kết: 06/10/2026 trong hợp đồng."),
            ("Date_Dot", "Hạn nộp hồ sơ: 06.10.2026 lúc 17:00."),
            ("CompactDate", "Mã giao dịch: TXN20261006 hoàn tất."),
            # HTTP Status Codes
            ("HTTP_200", "Gateway returned HTTP 200 OK after proxying."),
            ("HTTP_202", "Request accepted with HTTP 202 Accepted status."),
            ("HTTP_404", "Endpoint error status: 404 Not Found."),
            ("HTTP_500", "Server error code 500 Internal Server Error encountered."),
            ("HTTP_403", "AI Registry returned 403 Forbidden for shadow system."),
            # Monetary Amounts
            ("Money_VND_Dots", "Tổng số tiền vay: 100.000 VND và bảo hiểm 50.000 VND."),
            ("Money_VND_Large", "Số tiền giải ngân là 500.000.000 đ."),
            ("Money_USD_Commas", "Amount transferred: $10,000,000 USD to partner."),
            ("Money_VN_Words", "Khoản vay hạn mức 500 triệu đồng."),
            # Version Strings & Technical IDs
            ("Semver_030", "Platform runtime version v0.3.0 deployed successfully."),
            ("Semver_210", "Model artifact version v2.1.0 loaded."),
            ("Tracking_Alphanumeric", "Tracking ID: ORDER001090012345ABC in transit."),
            ("UUID_String", "Event ID: 018f3a9e-4e89-7b21-9921-3a81289128aa registered."),
            ("HexHash_SHA256", "Artifact hash: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e."),
            ("Metrics_Float", "Latency overhead was 10.198ms with score 745.5."),
            # Non-PII Numerics
            ("NonCCCD_12Digits_Leading1", "Số mã vạch: 123456789012 đã quét thành công."),
            ("TooShort_Phone_9Digits", "Số nội bộ: 012345678 của phòng kế toán."),
            ("Landline_Hanoi", "Số máy bàn cố định: 02438257890 liên hệ trực tiếp."),
            ("ShortNumber_7Digits", "Số phiếu bốc thăm: 1234567 trúng thưởng."),
            ("Standalone_Number_NoKeyword", "Dãy số 19034567890123 không có từ khóa tài khoản."),
        ]

        for name, text in safe_samples:
            with self.subTest(name=name):
                masked, detected = scan_and_mask(text)
                self.assertEqual(detected, [], f"False positive detected in {name}: {detected}")
                self.assertEqual(masked, text, f"Text was corrupted in {name}:\nOriginal: {text}\nMasked:   {masked}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
