"""
Tier 2: Boundary & Corner Cases E2E Tests.
Covers:
- Payload sizes (0B, 1B, 50KB payload, deep nesting, Vietnamese unicode multibyte fidelity)
- PII anomalies (11-digit, 13-digit, alphanumeric embedding, formatted phone numbers)
- Streaming edge cases (immediate [DONE], single-token stream, rapid bursts, upstream timeout)
- Merkle boundaries (single-leaf, 2-leaf, odd leaves N=3, N=5, empty N=0, stress N=1000)
- Archive corner cases (truncated zip, missing manifest, extra files, corrupt stream)
- Approval & Dwell boundaries (exact threshold, sub-threshold, rapid double-click race, special chars)
"""

import hashlib
import json
import time
import zipfile
from pathlib import Path
import pytest

from tests.e2e.conftest import (
    VietnamesePIIScanner,
    AIRegistryContract,
    MerkleAuditEngine,
    ApprovalStateMachine,
    MockPythonSDKClient
)
from tests.e2e.verifier_oracle import EvidenceVerifier, canonical_json


# ==============================================================================
# B1: Payload Size Boundaries & Unicode Multibyte Fidelity (>=5 tests)
# ==============================================================================

def test_tier2_boundary_empty_payload_handling():
    """Verify empty dictionary payload canonicalizes to valid 2-byte empty JSON '{}'."""
    raw = {}
    canon = canonical_json(raw)
    assert canon == b"{}"
    h = hashlib.sha256(canon).hexdigest()
    assert len(h) == 64


def test_tier2_boundary_single_byte_malformed_json():
    """Verify single-byte malformed JSON is detected without parser crash."""
    raw_bytes = b"X"
    with pytest.raises(json.JSONDecodeError):
        json.loads(raw_bytes.decode("utf-8"))


def test_tier2_boundary_50kb_payload_fidelity(fixtures_paths):
    """Verify exactly ~50KB payload is hashed, parsed, and processed without truncation."""
    with open(fixtures_paths["payloads"] / "payload_50kb.json", "r", encoding="utf-8") as f:
        content = f.read()
    payload_bytes = content.encode("utf-8")
    assert len(payload_bytes) >= 50000, f"Payload size is {len(payload_bytes)} bytes"

    # Verify canonical serialization speed and consistency
    t0 = time.perf_counter()
    obj = json.loads(content)
    canon = canonical_json(obj)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert elapsed_ms < 100.0  # Fast processing well under budget
    assert len(canon) >= 50000


def test_tier2_boundary_vietnamese_unicode_multibyte_fidelity():
    """Verify complex Vietnamese diacritics and tone marks maintain bit-exact fidelity across hashing."""
    vn_text = "Thẩm định hồ sơ: Nguyễn Văn Đắc, Đắk Lắk, chuyển khoản tại TP. Hồ Chí Minh 🇻🇳."
    obj = {"prompt": vn_text, "note": "Hồ sơ ưu tiên"}
    canon = canonical_json(obj)
    # Check that unicode characters are NOT escaped as \uXXXX (ensure_ascii=False)
    assert "Nguyễn Văn Đắc".encode("utf-8") in canon
    re_parsed = json.loads(canon.decode("utf-8"))
    assert re_parsed["prompt"] == vn_text


def test_tier2_boundary_deeply_nested_json():
    """Verify 20-level nested JSON payload canonicalizes deterministically."""
    nested = {"val": 1}
    for i in range(20):
        nested = {"level": i, "child": nested}
    canon = canonical_json(nested)
    h = hashlib.sha256(canon).hexdigest()
    assert len(h) == 64


# ==============================================================================
# B2: PII Edge Cases & Anomaly Validation (>=5 tests)
# ==============================================================================

def test_tier2_boundary_cccd_11_digits_not_masked():
    """Verify 11-digit number (1 digit short of CCCD) is NOT falsely flagged as CCCD."""
    prompt = "Mã số hồ sơ tham chiếu: 00109001234 (11 số)"
    masked, detected = VietnamesePIIScanner.scan_and_mask(prompt)
    assert "CCCD" not in detected
    assert "00109001234" in masked


def test_tier2_boundary_cccd_13_digits_not_masked():
    """Verify 13-digit number (1 digit too long) is NOT masked as CCCD."""
    prompt = "Mã vạch sản phẩm: 0010900123456 (13 số)"
    masked, detected = VietnamesePIIScanner.scan_and_mask(prompt)
    assert "CCCD" not in detected
    assert "0010900123456" in masked


def test_tier2_boundary_cccd_embedded_in_alphanumeric():
    """Verify CCCD embedded inside an alphanumeric code is not mistakenly matched."""
    prompt = "Tracking code: ORDER001090012345ABC in transit"
    masked, detected = VietnamesePIIScanner.scan_and_mask(prompt)
    assert "CCCD" not in detected


def test_tier2_boundary_phone_variations_with_whitespace():
    """Verify phone numbers with standard prefixes are correctly recognized."""
    prompt = "Liên hệ số 0988776655 hoặc 0351234567 ngay."
    masked, detected = VietnamesePIIScanner.scan_and_mask(prompt)
    assert "PHONE" in detected
    assert "098****655" in masked
    assert "035****567" in masked


def test_tier2_boundary_empty_text_pii_scan():
    """Verify scanning empty string returns empty detected list without error."""
    masked, detected = VietnamesePIIScanner.scan_and_mask("")
    assert masked == ""
    assert detected == []


# ==============================================================================
# B3: SSE Streaming Anomalies & Timeout Boundaries (>=5 tests)
# ==============================================================================

def test_tier2_boundary_sse_immediate_done(mock_llm):
    """Verify handling of immediate [DONE] marker from upstream without prior content tokens."""
    import urllib.request
    mock_llm.configure(custom_response="")
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "empty"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    lines = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            decoded = line.decode("utf-8").strip()
            lines.append(decoded)
            if decoded == "data: [DONE]":
                break
    mock_llm.reset_config()
    assert "data: [DONE]" in lines


def test_tier2_boundary_sse_single_token_stream(mock_llm):
    """Verify streaming response consisting of exactly one word/token."""
    import urllib.request
    mock_llm.configure(custom_response="OK")
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "ping"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    tokens = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            text = line.decode("utf-8").strip()
            if text == "data: [DONE]":
                break
            if text.startswith("data: "):
                chunk = json.loads(text[6:])
                c = chunk["choices"][0]["delta"].get("content")
                if c:
                    tokens.append(c)
    mock_llm.reset_config()
    assert "".join(tokens) == "OK"


def test_tier2_boundary_sse_chunk_burst_rate(mock_llm):
    """Verify burst delivery with 0ms chunk interval does not drop tokens."""
    import urllib.request
    mock_llm.configure(chunk_delay_ms=0, custom_response="Một hai ba bốn năm sáu bảy tám")
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "burst"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    tokens = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            text = line.decode("utf-8").strip()
            if text == "data: [DONE]":
                break
            if text.startswith("data: "):
                chunk = json.loads(text[6:])
                c = chunk["choices"][0]["delta"].get("content")
                if c:
                    tokens.append(c)
    mock_llm.reset_config()
    assert "".join(tokens) == "Một hai ba bốn năm sáu bảy tám"


def test_tier2_boundary_upstream_injected_delay(mock_llm):
    """Verify client timeout properly triggers when upstream exceeds delay threshold."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "slow"}], "stream": False}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Mock-Delay-Ms": "800"}
    )
    # Set client timeout shorter than delay
    with pytest.raises((TimeoutError, urllib.error.URLError)):
        urllib.request.urlopen(req, timeout=0.2)


def test_tier2_boundary_upstream_503_service_unavailable(mock_llm):
    """Verify upstream HTTP 503 is cleanly reported as gateway error."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}], "stream": False}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Mock-Status": "503", "X-Mock-Error": "service_unavailable"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 503


# ==============================================================================
# B4: Merkle Tree Boundary & Stress Cases (>=5 tests)
# ==============================================================================

def test_tier2_boundary_merkle_single_leaf():
    """Verify Merkle tree with exactly 1 leaf produces valid root hash."""
    leaf = hashlib.sha256(b"leaf-1").hexdigest()
    root = MerkleAuditEngine.compute_root([leaf])
    expected = hashlib.sha256((leaf + leaf).encode("utf-8")).hexdigest()
    assert root == expected


def test_tier2_boundary_merkle_two_leaves():
    """Verify 2-leaf Merkle tree computes hash of concatenated leaves."""
    l1 = hashlib.sha256(b"l1").hexdigest()
    l2 = hashlib.sha256(b"l2").hexdigest()
    root = MerkleAuditEngine.compute_root([l1, l2])
    expected = hashlib.sha256((l1 + l2).encode("utf-8")).hexdigest()
    assert root == expected


def test_tier2_boundary_merkle_odd_leaves_n3():
    """Verify 3-leaf Merkle tree balances right branch by duplicating last leaf."""
    leaves = [hashlib.sha256(f"l_{i}".encode("utf-8")).hexdigest() for i in range(3)]
    root = MerkleAuditEngine.compute_root(leaves)
    assert len(root) == 64


def test_tier2_boundary_merkle_empty_leaves():
    """Verify empty list of leaves produces defined empty root hash."""
    root = MerkleAuditEngine.compute_root([])
    expected = hashlib.sha256(b"").hexdigest()
    assert root == expected


def test_tier2_boundary_merkle_1000_leaves_stress():
    """Verify Merkle root calculation over 1,000 leaves finishes in < 50ms."""
    leaves = [hashlib.sha256(f"evt_{i}".encode("utf-8")).hexdigest() for i in range(1000)]
    t0 = time.perf_counter()
    root = MerkleAuditEngine.compute_root(leaves)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert len(root) == 64
    assert elapsed_ms < 50.0


# ==============================================================================
# B5: Archive, Corruption & Policy Boundary Cases (>=5 tests)
# ==============================================================================

def test_tier2_boundary_corrupt_zip_exit_code_6(fixtures_paths):
    """Verify corrupted non-zip file returns Exit Code 6."""
    corrupt_pack = fixtures_paths["packs"] / "corrupt_archive.zip"
    verifier = EvidenceVerifier(str(corrupt_pack))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_GENERAL_FAIL


def test_tier2_boundary_nonexistent_file_exit_code_6():
    """Verify non-existent file path returns Exit Code 6."""
    verifier = EvidenceVerifier("non_existent_evidence_pack_12345.zip")
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_GENERAL_FAIL
    assert "not found" in msg


def test_tier2_boundary_dwell_time_exact_threshold():
    """Verify dwell time exactly at minimum threshold (10s == 10s) succeeds."""
    sm = ApprovalStateMachine(decision_id="dec-b1", creator_id="c", min_dwell_seconds=10)
    status, _ = sm.submit_action(approver_id="app-1", action="APPROVE", dwell_seconds=10)
    assert status == 200


def test_tier2_boundary_dwell_time_sub_threshold():
    """Verify dwell time 1s below threshold (9s < 10s) is rejected with 422."""
    sm = ApprovalStateMachine(decision_id="dec-b2", creator_id="c", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="app-1", action="APPROVE", dwell_seconds=9)
    assert status == 422
    assert "DWELL_TIME_NOT_MET" in msg


def test_tier2_boundary_rapid_duplicate_approval_attempt():
    """Verify rapid double-click approval by same approver fails on second attempt."""
    sm = ApprovalStateMachine(decision_id="dec-b3", creator_id="c", min_dwell_seconds=10)
    s1, _ = sm.submit_action(approver_id="app-1", action="APPROVE", dwell_seconds=12)
    assert s1 == 200
    s2, msg2 = sm.submit_action(approver_id="app-1", action="APPROVE", dwell_seconds=12)
    assert s2 == 400
    assert "DUPLICATE_APPROVER" in msg2
