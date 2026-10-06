"""Unit tests for Vietnamese PII scanner and masking engine."""

import pytest

from ai_evidence_sdk.pii import (
    LABEL_BANK_ACCOUNT,
    LABEL_CCCD,
    LABEL_PHONE,
    PIIValidator,
    VietnamesePIIScanner,
    sanitize,
    mask_bank_account,
    mask_cccd,
    mask_phone,
    scan_and_mask,
    scan_dict,
)


def test_pii_cccd_masking():
    raw = "Khách hàng có CCCD 001090012345 tại Hà Nội"
    masked, labels = scan_and_mask(raw)
    assert "001******345" in masked
    assert "001090012345" not in masked
    assert labels == [LABEL_CCCD]


def test_pii_domestic_phone_masking():
    raw = "Liên hệ số điện thoại 0912345678 ngay"
    masked, labels = scan_and_mask(raw)
    assert "091****678" in masked
    assert "0912345678" not in masked
    assert labels == [LABEL_PHONE]


def test_pii_international_phone_masking():
    raw = "Hotline +84903112233 hỗ trợ 24/7"
    masked, labels = scan_and_mask(raw)
    assert "+8490****233" in masked
    assert "+84903112233" not in masked
    assert labels == [LABEL_PHONE]


def test_pii_bank_account_masking():
    raw1 = "Chuyển tiền vào STK 123456789012 ngân hàng VCB"
    masked1, labels1 = scan_and_mask(raw1)
    assert "STK 1234******9012" in masked1
    assert "123456789012" not in masked1
    assert labels1 == [LABEL_BANK_ACCOUNT]

    raw2 = "Tài khoản: 9876543210 chi nhánh Ba Đình"
    masked2, labels2 = scan_and_mask(raw2)
    assert "9876******3210" in masked2
    assert labels2 == [LABEL_BANK_ACCOUNT]


def test_pii_combined_all_categories():
    raw = "Hồ sơ: CCCD 001090012345, SĐT 0987654321, STK 102030405060 VietinBank"
    masked, labels = scan_and_mask(raw)
    assert "001******345" in masked
    assert "098****321" in masked
    assert "1020******5060" in masked
    assert labels == [LABEL_BANK_ACCOUNT, LABEL_CCCD, LABEL_PHONE]


def test_pii_scan_dict_nested():
    data = {
        "customer_name": "Nguyen Van A",
        "identity": {
            "cccd_number": "001090012345",
            "phones": ["0912345678", "+84988776655"],
        },
        "financial": {
            "bank_note": "Chuyển lương qua STK 998877665544",
            "income": 50000000,
        },
    }

    masked, labels = scan_dict(data)
    assert labels == [LABEL_BANK_ACCOUNT, LABEL_CCCD, LABEL_PHONE]
    assert masked["identity"]["cccd_number"] == "001******345"
    assert masked["identity"]["phones"][0] == "091****678"
    assert masked["identity"]["phones"][1] == "+8498****655"
    assert "STK 9988******5544" in masked["financial"]["bank_note"]
    assert masked["financial"]["income"] == 50000000  # Number preserved


def test_pii_no_pii_clean():
    raw = "Thông tin chung không chứa dữ liệu cá nhân"
    masked, labels = scan_and_mask(raw)
    assert masked == raw
    assert labels == []


def test_pii_zero_width_space_evasion_defeated():
    # CCCD with zero-width spaces (\u200b, \u200c, \u200d)
    raw_cccd = "Khách hàng CCCD 0\u200b01090012345 cần giải ngân"
    masked_cccd, labels_cccd = scan_and_mask(raw_cccd)
    assert "001******345" in masked_cccd
    assert labels_cccd == [LABEL_CCCD]

    # Phone with soft hyphen (\u00ad) and zero-width no-break space (\ufeff)
    raw_phone = "Liên hệ 0\u00ad912\ufeff345678"
    masked_phone, labels_phone = scan_and_mask(raw_phone)
    assert "091****678" in masked_phone
    assert labels_phone == [LABEL_PHONE]

    # Bank account with zero-width characters
    raw_bank = "STK: 1\u200b9034567890123 Techcombank"
    masked_bank, labels_bank = scan_and_mask(raw_bank)
    assert "1903******0123" in masked_bank
    assert labels_bank == [LABEL_BANK_ACCOUNT]


def test_pii_fullwidth_unicode_digits_normalized():
    # Full-width CCCD: ００１０９００１２３４５
    fullwidth_cccd = "".join(chr(0xFF10 + int(d)) for d in "001090012345")
    raw = f"Số căn cước: {fullwidth_cccd}"
    masked, labels = scan_and_mask(raw)
    assert "001******345" in masked
    assert labels == [LABEL_CCCD]

    # Full-width Phone: ０９１２３４５６７８
    fullwidth_phone = "".join(chr(0xFF10 + int(d)) for d in "0912345678")
    raw_p = f"Hotline: {fullwidth_phone}"
    masked_p, labels_p = scan_and_mask(raw_p)
    assert "091****678" in masked_p
    assert labels_p == [LABEL_PHONE]


def test_vietnamese_pii_scanner_class_methods():
    raw = "CCCD: 0\u200b01090012345 và hotline ０９１２３４５６７８"
    # Test scan() method
    detected = VietnamesePIIScanner.scan(raw)
    assert detected == [LABEL_CCCD, LABEL_PHONE]

    # Test scan_and_mask() method
    masked, labels = VietnamesePIIScanner.scan_and_mask(raw)
    assert "001******345" in masked
    assert "091****678" in masked
    assert labels == [LABEL_CCCD, LABEL_PHONE]

    # Test sanitize()
    assert VietnamesePIIScanner.sanitize("０\u200b１２") == "012"

