"""Vietnamese PII scanner and masking engine matching Go Gateway rules."""

import re
import unicodedata
from typing import Any, Dict, List, Tuple

LABEL_BANK_ACCOUNT = "BANK_ACCOUNT"
LABEL_CCCD = "CCCD"
LABEL_PHONE = "PHONE"

# Exact regex specifications matching Go Gateway (services/gateway/internal/pii/scanner.go)
# Bank Account: 8 to 16 digits preceded by keywords STK, TK, tài khoản, tai khoan, account
BANK_REGEX = re.compile(
    r"(?i)(?:STK|TK|tài khoản|tai khoan|account)[\s:]*([0-9]{8,16})"
)

# 12-digit CCCD: starts with 0, followed by 11 digits
CCCD_REGEX = re.compile(r"\b0\d{11}\b")

# Phone: +84 followed by [3,5,7,8,9] and 8 digits, or domestic 0 followed by [3,5,7,8,9] and 8 digits
PHONE_REGEX = re.compile(r"(?:\+84[35789]\d{8}|\b0[35789]\d{8})\b")

# Zero-width and invisible unicode codepoints
ZERO_WIDTH_REGEX = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]")


def sanitize(text: str) -> str:
    """
    Normalizes input text prior to PII scanning:
    1. Strips zero-width and invisible unicode characters (\u200b, \u200c, \u200d, \ufeff, \u00ad).
    2. Normalizes full-width digits and characters via NFKC.
    """
    if not text:
        return ""
    cleaned = ZERO_WIDTH_REGEX.sub("", text)
    return unicodedata.normalize("NFKC", cleaned)


def mask_cccd(val: str) -> str:
    """Masks a 12-digit CCCD string to retain first 3 and last 3 digits."""
    if len(val) < 6:
        return val
    return val[:3] + "******" + val[-3:]


def mask_phone(val: str) -> str:
    """
    Masks a phone number string:
    - Domestic (0912345678): 091****678
    - International (+84903112233): +8490****233
    """
    if val.startswith("+84"):
        if len(val) >= 8:
            return val[:5] + "****" + val[-3:]
    elif val.startswith("0"):
        if len(val) >= 6:
            return val[:3] + "****" + val[-3:]
    return val


def mask_bank_account(val: str) -> str:
    """Masks an 8-16 digit bank account number to retain first 4 and last 4 digits."""
    if len(val) >= 8:
        return val[:4] + "******" + val[-4:]
    return "******"


def scan_and_mask(text: str) -> Tuple[str, List[str]]:
    """
    Scans the input text following the strict disambiguation hierarchy:
    1. Bank Account (with context keywords)
    2. 12-digit CCCD
    3. Domestic & International Phone
    Returns the sanitized text and a sorted, deduplicated list of detected PII labels.
    """
    if not text:
        return "", []

    result = sanitize(text)
    if not result:
        return "", []

    detected_set = set()

    # 1. Bank Account (Right-to-left replacement of capture group 1 to preserve byte offsets)
    matches = list(BANK_REGEX.finditer(result))
    if matches:
        for m in reversed(matches):
            acc_digits = m.group(1)
            start, end = m.start(1), m.end(1)
            masked_acc = mask_bank_account(acc_digits)
            result = result[:start] + masked_acc + result[end:]
            detected_set.add(LABEL_BANK_ACCOUNT)

    # 2. CCCD (12 digits starting with 0)
    if CCCD_REGEX.search(result):
        def _replace_cccd(m: re.Match) -> str:
            detected_set.add(LABEL_CCCD)
            return mask_cccd(m.group(0))

        result = CCCD_REGEX.sub(_replace_cccd, result)

    # 3. Phone (+84 or 0 prefix)
    if PHONE_REGEX.search(result):
        def _replace_phone(m: re.Match) -> str:
            detected_set.add(LABEL_PHONE)
            return mask_phone(m.group(0))

        result = PHONE_REGEX.sub(_replace_phone, result)

    return result, sorted(list(detected_set))


def _mask_value(v: Any) -> Tuple[Any, List[str]]:
    if isinstance(v, str):
        return scan_and_mask(v)
    elif isinstance(v, dict):
        return scan_dict(v)
    elif isinstance(v, list):
        detected_all = []
        new_list = []
        for item in v:
            m_item, d_items = _mask_value(item)
            new_list.append(m_item)
            detected_all.extend(d_items)
        return new_list, detected_all
    else:
        return v, []


def scan_dict(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Recursively scans and masks dictionary values for CCCD, Phone, and Bank Account numbers.
    Returns a tuple of (masked_dict, sorted_detected_types).
    """
    if not isinstance(data, dict):
        return data, []

    detected_set = set()
    output: Dict[str, Any] = {}

    for k, v in data.items():
        masked_val, detected = _mask_value(v)
        output[k] = masked_val
        for d in detected:
            detected_set.add(d)

    return output, sorted(list(detected_set))


class VietnamesePIIScanner:
    """Production scanner and mask validator for Vietnamese PII matching Go Gateway rules."""

    CCCD_REGEX = CCCD_REGEX
    PHONE_REGEX = PHONE_REGEX
    BANK_REGEX = BANK_REGEX

    sanitize = staticmethod(sanitize)
    scan_and_mask = staticmethod(scan_and_mask)

    @staticmethod
    def scan(text: str) -> List[str]:
        """Scans input text and returns sorted list of detected PII labels without masking."""
        _, detected = scan_and_mask(text)
        return detected

    scan_dict = staticmethod(scan_dict)
    mask_cccd = staticmethod(mask_cccd)
    mask_phone = staticmethod(mask_phone)
    mask_bank_account = staticmethod(mask_bank_account)


# Retain PIIValidator alias for backward compatibility
PIIValidator = VietnamesePIIScanner

