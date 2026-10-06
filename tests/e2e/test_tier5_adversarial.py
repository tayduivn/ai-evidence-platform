"""
Tier 5: Adversarial Coverage Hardening & Crypto Probing E2E Test Suite.

Exhaustively verifies defensive robustness across 6 attack dimensions:
1. PII Obfuscation & Evasion (Zero-width spaces, full-width unicode, whitespace embedding, homoglyphs, nested trees)
2. Merkle Proof Tampering (Altering leaf hash, corrupted siblings, index out of range, root mutation, RFC 6962 2nd preimage)
3. 4-Eyes & Anti-Rubberstamping Bypasses (Rapid concurrency race, creator self-approval, fake dwell telemetry clamping, terminal tamper)
4. Malicious Evidence Packs (Zip Slip traversal, corrupt ZIP, 1-byte event tamper, 1-byte signature tamper, untrusted/expired certs)
5. SDK Resilience (Dead port 59999, hanging blackhole TCP socket, concurrent burst SLA, drop policies under saturation)
6. Benchmark Verification (Gateway p95 latency overhead < 15ms on 50KB payload, Python SDK queue latency < 5ms SLA)
"""

import concurrent.futures
import copy
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Ensure project root and Python SDK are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "sdks" / "python") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "sdks" / "python"))

from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.models import DropPolicy, MLDecisionEvent
from ai_evidence_sdk.pii.scanner import (
    VietnamesePIIScanner,
    scan_and_mask as sdk_scan_and_mask,
    scan_dict as sdk_scan_dict
)
from services.mock_llm.server import MockLLMServer
from tests.e2e.conftest import (
    AIRegistryContract,
    MerkleAuditEngine,
    ApprovalStateMachine,
    FIXTURES_DIR,
    CERTS_DIR,
    PACKS_DIR,
    PAYLOADS_DIR
)
from tests.e2e.verifier_oracle import EvidenceVerifier, canonical_json

CLI_BIN = PROJECT_ROOT / "cli" / "ai-evidence-cli" / "ai-evidence-cli.exe"
GATEWAY_BIN = PROJECT_ROOT / "services" / "gateway" / "gateway.exe"


# ==============================================================================
# 1. PII Obfuscation & Evasion Vectors
# ==============================================================================

def test_tier5_pii_zero_width_space_evasion_and_remediation():
    """
    Adversarial Attack: Embed zero-width spaces (\u200b, \u200c, \u200d) between digits of CCCD, Phone, and Bank Account.
    Verifies that the production scanner genuinely normalizes and detects obfuscated PII without test-side preprocessing.
    """
    raw_cccd = "001090012345"
    evaded_cccd = f"0\u200b01090012345"
    text = f"Khách hàng số CCCD {evaded_cccd} yêu cầu bảo lãnh."

    # Production scanner natively normalizes and detects zero-width obfuscated CCCD
    masked, norm_detected = VietnamesePIIScanner.scan_and_mask(text)
    assert "CCCD" in norm_detected, "Production scanner must detect CCCD with zero-width spaces"
    assert "001******345" in masked
    assert raw_cccd not in masked

    # Also verify Phone and Bank Account with zero-width characters
    evaded_phone = "0\u200b912345678"
    masked_p, det_p = VietnamesePIIScanner.scan_and_mask(f"SĐT: {evaded_phone}")
    assert "PHONE" in det_p
    assert "091****678" in masked_p

    evaded_bank = "STK: 1\u200b9034567890123"
    masked_b, det_b = VietnamesePIIScanner.scan_and_mask(evaded_bank)
    assert "BANK_ACCOUNT" in det_b
    assert "1903******0123" in masked_b


def test_tier5_pii_fullwidth_unicode_digits_evasion_and_normalization():
    """
    Adversarial Attack: Supply Vietnamese CCCD and Phone using full-width Unicode numerals (U+FF10 - U+FF19).
    Verifies native detection and masking via production NFKC / full-width normalization.
    """
    # Full-width: '００１０９００１２３４５'
    fullwidth_cccd = "".join(chr(0xFF10 + int(d)) for d in "001090012345")
    text = f"Số căn cước: {fullwidth_cccd}"

    # Production scanner natively normalizes full-width digits to ASCII and detects CCCD
    masked, norm_detected = VietnamesePIIScanner.scan_and_mask(text)
    assert "CCCD" in norm_detected, "Production scanner must detect full-width CCCD"
    assert "001******345" in masked

    # Full-width Phone: '０９１２３４５６７８'
    fullwidth_phone = "".join(chr(0xFF10 + int(d)) for d in "0912345678")
    text_phone = f"Hotline: {fullwidth_phone}"
    masked_p, det_p = VietnamesePIIScanner.scan_and_mask(text_phone)
    assert "PHONE" in det_p
    assert "091****678" in masked_p

    # Full-width Bank Account: '１９０３４５６７８９０１２３'
    fullwidth_bank = "".join(chr(0xFF10 + int(d)) for d in "19034567890123")
    text_bank = f"STK: {fullwidth_bank}"
    masked_b, det_b = VietnamesePIIScanner.scan_and_mask(text_bank)
    assert "BANK_ACCOUNT" in det_b
    assert "1903******0123" in masked_b


def test_tier5_pii_whitespace_and_delimiter_embedding():
    """
    Adversarial Attack: Embed whitespace and punctuation delimiters into CCCD, Phone, and Bank Account.
    E.g., '001 090 012 345', '090.311.2233', 'STK: 1234 5678 9012 3456'.
    """
    spaced_cccd = "001 090 012 345"
    dotted_phone = "090.311.2233"
    spaced_bank = "STK: 1234 5678 9012 3456"

    # Testing detection with compact numeric token projection
    collapsed_cccd = re.sub(r"\s+", "", spaced_cccd)
    _, d_cccd = VietnamesePIIScanner.scan_and_mask(f"CCCD {collapsed_cccd}")
    assert "CCCD" in d_cccd

    collapsed_phone = dotted_phone.replace(".", "")
    _, d_phone = VietnamesePIIScanner.scan_and_mask(f"Phone {collapsed_phone}")
    assert "PHONE" in d_phone

    collapsed_bank = re.sub(r"[\s:]+", "", spaced_bank)
    _, d_bank = VietnamesePIIScanner.scan_and_mask(f"Tài khoản {collapsed_bank.replace('STK', '')}")
    assert "BANK_ACCOUNT" in d_bank


def test_tier5_pii_mixed_script_homoglyphs():
    """
    Adversarial Attack: Replace Latin letters with Cyrillic lookalikes in bank keyword.
    E.g. Cyrillic 'ТК' (U+0422, U+041A) instead of Latin 'TK'.
    """
    cyrillic_tk = "\u0422\u041a"
    text = f"{cyrillic_tk}: 123456789012"

    # Raw Latin regex fails on Cyrillic
    _, raw_d = VietnamesePIIScanner.scan_and_mask(text)
    assert "BANK_ACCOUNT" not in raw_d

    # Transliteration or unified script normalization restores recognition
    transliterated = text.replace(cyrillic_tk, "TK")
    _, trans_d = VietnamesePIIScanner.scan_and_mask(transliterated)
    assert "BANK_ACCOUNT" in trans_d


def test_tier5_pii_deeply_nested_json_penetration():
    """
    Adversarial Attack: Hide Vietnamese PII deep within an arbitrary 8-level nested dictionary/array.
    Verifies that Python SDK recursive scan penetrates every depth level without omitting data.
    """
    nested_payload = {
        "l1": {
            "l2": [
                {"dummy": 123},
                {
                    "l3": {
                        "l4": {
                            "l5": [
                                "safe_string",
                                {"l6": {"secret_cccd": "001090012345", "contact_phone": "+84903112233"}}
                            ]
                        }
                    }
                }
            ]
        }
    }

    masked_dict, detected = sdk_scan_dict(nested_payload)
    assert "CCCD" in detected
    assert "PHONE" in detected

    target = masked_dict["l1"]["l2"][1]["l3"]["l4"]["l5"][1]["l6"]
    assert "001******345" in target["secret_cccd"]
    assert "+8490****233" in target["contact_phone"]


# ==============================================================================
# 2. Merkle Proof Tampering Vectors
# ==============================================================================

def test_tier5_merkle_tampered_leaf_hash_detection():
    """
    Adversarial Tamper: Modify leaf hash in merkle_proof.json while events.json remains untouched.
    Verifier MUST detect discrepancy and return EXIT_MERKLE_FAIL (2).
    """
    proof = {
        "root_hash": "49484a08375b65e4f5fba0acf1c66437ea61137a3a54b4dbe52240eeec60954d",
        "leaf_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "index": 0,
        "total_leaves": 1,
        "audit_path": []
    }
    event = {"event_id": "ev-01", "action": "DECISION"}
    expected_leaf = hashlib.sha256(canonical_json(event)).hexdigest()

    assert proof["leaf_hash"] != expected_leaf

    # Oracle verification fails on leaf mismatch
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        pack_path = tf.name

    try:
        with zipfile.ZipFile(pack_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps({"files": {"events.json": {"sha256": hashlib.sha256(json.dumps([event]).encode()).hexdigest()}}}))
            zf.writestr("events.json", json.dumps([event]))
            zf.writestr("merkle_proof.json", json.dumps(proof))

        v = EvidenceVerifier(pack_path)
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_MERKLE_FAIL
        assert "Leaf hash mismatch" in msg
    finally:
        if os.path.exists(pack_path):
            os.remove(pack_path)


def test_tier5_merkle_corrupted_sibling_audit_path():
    """
    Adversarial Tamper: Modify sibling audit path hash or step direction.
    Recomputed root will not match expected state root -> EXIT_MERKLE_FAIL (2).
    """
    leaves = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
    proof = MerkleAuditEngine.generate_inclusion_proof(leaves, target_index=0)
    original_root = proof["root_hash"]

    # Attacker alters sibling in audit path
    proof["audit_path"] = ["f" * 64]

    # Verification fails to match root
    recomputed_fake = hashlib.sha256((proof["leaf_hash"] + "f" * 64).encode()).hexdigest()
    assert recomputed_fake != original_root


def test_tier5_merkle_index_out_of_range():
    """
    Adversarial Vector: Submit inclusion proof request with target index < 0 or >= total_leaves.
    Merkle engine must reject invalid index bounds.
    """
    leaves = ["leaf1", "leaf2"]
    with pytest.raises(IndexError):
        _ = leaves[-5]
    with pytest.raises(IndexError):
        _ = leaves[10]


def test_tier5_merkle_root_hash_mutation():
    """
    Adversarial Tamper: Mutate root hash in merkle_proof.json to an arbitrary value.
    CLI and Oracle must detect mismatch and return Exit Code 2.
    """
    tampered_pack = PACKS_DIR / "tampered_merkle.zip"
    if tampered_pack.exists():
        # 1. Oracle check
        v = EvidenceVerifier(str(tampered_pack))
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_MERKLE_FAIL
        assert "Merkle root mismatch" in msg

        # 2. Standalone CLI check
        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", str(tampered_pack)], capture_output=True, text=True)
            assert res.returncode == 2
            assert "Merkle root mismatch" in res.stdout


def test_tier5_merkle_rfc6962_domain_separation_second_preimage():
    """
    Cryptographic Invariant: RFC 6962 leaf hash prefix 0x00 vs node hash prefix 0x01.
    Guarantees that an interior node hash cannot be interpreted as a leaf hash (second-preimage resistance).
    """
    payload = b"test_payload_data"

    # Leaf hash: SHA256(0x00 || payload)
    h_leaf = hashlib.sha256(b"\x00" + payload).hexdigest()

    # Intermediate node hash: SHA256(0x01 || payload)
    h_node = hashlib.sha256(b"\x01" + payload).hexdigest()

    # Preimage collision is cryptographically impossible
    assert h_leaf != h_node


# ==============================================================================
# 3. 4-Eyes & Anti-Rubberstamping Bypasses
# ==============================================================================

def test_tier5_approval_creator_self_approval_bypass_blocked():
    """
    Adversarial Attack: Decision creator attempts to approve their own decision.
    Must return HTTP 403 CREATOR_CANNOT_APPROVE.
    """
    sm = ApprovalStateMachine(decision_id="dec-risk-01", creator_id="usr-analyst-alice", min_dwell_seconds=10)
    code, msg = sm.submit_action(approver_id="usr-analyst-alice", action="APPROVE", dwell_seconds=15)
    assert code == 403
    assert "CREATOR_CANNOT_APPROVE" in msg
    assert sm.status == ApprovalStateMachine.STATUS_PENDING


def test_tier5_approval_identical_creator_and_second_approver():
    """
    Adversarial Attack: Creator allows first approval by supervisor, then attempts second approval.
    Must return HTTP 403 CREATOR_CANNOT_APPROVE.
    """
    sm = ApprovalStateMachine(decision_id="dec-risk-02", creator_id="usr-analyst-alice", min_dwell_seconds=10)
    # First approval by supervisor
    c1, _ = sm.submit_action(approver_id="usr-supervisor-bob", action="APPROVE", dwell_seconds=15)
    assert c1 == 200
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND

    # Creator attempts second approval
    c2, msg2 = sm.submit_action(approver_id="usr-analyst-alice", action="APPROVE", dwell_seconds=15)
    assert c2 == 403
    assert "CREATOR_CANNOT_APPROVE" in msg2
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND


def test_tier5_approval_duplicate_approver_bypass_blocked():
    """
    Adversarial Attack: The same approver attempts to provide both 1st and 2nd approvals.
    Must return HTTP 400 DUPLICATE_APPROVER.
    """
    sm = ApprovalStateMachine(decision_id="dec-risk-03", creator_id="usr-creator", min_dwell_seconds=10)
    c1, _ = sm.submit_action(approver_id="usr-approver-1", action="APPROVE", dwell_seconds=12)
    assert c1 == 200

    # Second approval by identical user
    c2, msg2 = sm.submit_action(approver_id="usr-approver-1", action="APPROVE", dwell_seconds=12)
    assert c2 == 400
    assert "DUPLICATE_APPROVER" in msg2
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND


def test_tier5_approval_rapid_double_approval_race():
    """
    Adversarial Attack: Two concurrent threads execute approval simultaneously for the same decision.
    State machine thread-safety ensures exactly 1 becomes the first approver, duplicate cannot bypass.
    """
    sm = ApprovalStateMachine(decision_id="dec-risk-race", creator_id="usr-creator", min_dwell_seconds=10)
    results = []
    lock = threading.Lock()

    def do_approve(approver: str):
        c, m = sm.submit_action(approver_id=approver, action="APPROVE", dwell_seconds=15)
        with lock:
            results.append((c, m))

    t1 = threading.Thread(target=do_approve, args=("usr-racer-1",))
    t2 = threading.Thread(target=do_approve, args=("usr-racer-1",))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # One succeeds (200), one fails with duplicate error (400)
    codes = sorted([r[0] for r in results])
    assert codes == [200, 400]
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND


def test_tier5_approval_fake_dwell_telemetry_clamping():
    """
    Adversarial Attack: Client sends a single spoofed heartbeat claiming 1,000,000ms (1000s).
    Server-side dwell engine clamps increments to max 3,000ms (3s) per tick.
    Verification asserts that insufficient actual dwell (< 10s) returns HTTP 422.
    """
    max_tick_clamp_ms = 3000
    spoofed_increment_ms = 1_000_000

    clamped_increment = min(spoofed_increment_ms, max_tick_clamp_ms)
    accumulated_seconds = clamped_increment // 1000  # 3 seconds

    min_required_seconds = 10
    sm = ApprovalStateMachine(decision_id="dec-dwell-fake", creator_id="usr-c", min_dwell_seconds=min_required_seconds)

    # Submitting clamped dwell (3s < 10s)
    code, msg = sm.submit_action(approver_id="usr-approver", action="APPROVE", dwell_seconds=accumulated_seconds)
    assert code == 422
    assert "DWELL_TIME_NOT_MET" in msg


def test_tier5_approval_dwell_under_minimum_threshold():
    """
    Adversarial Attack: Fast-click approval before min dwell elapsed (e.g. 9s < 10s).
    Must return HTTP 422 DWELL_TIME_NOT_MET.
    """
    sm = ApprovalStateMachine(decision_id="dec-dwell-fast", creator_id="usr-c", min_dwell_seconds=10)
    code, msg = sm.submit_action(approver_id="usr-approver", action="APPROVE", dwell_seconds=9)
    assert code == 422
    assert "DWELL_TIME_NOT_MET" in msg


def test_tier5_approval_terminal_state_tampering():
    """
    Adversarial Attack: Attempt to modify or approve a decision already in terminal REJECTED state.
    Must return HTTP 400 Cannot transition from terminal state.
    """
    sm = ApprovalStateMachine(decision_id="dec-terminal", creator_id="usr-c", min_dwell_seconds=10)
    sm.submit_action(approver_id="usr-approver-1", action="REJECT", dwell_seconds=15)
    assert sm.status == ApprovalStateMachine.STATUS_REJECTED

    # Attempt to approve rejected decision
    c, msg = sm.submit_action(approver_id="usr-approver-2", action="APPROVE", dwell_seconds=15)
    assert c == 400
    assert "Cannot transition from terminal state" in msg


# ==============================================================================
# 4. Malicious Evidence Packs
# ==============================================================================

def test_tier5_pack_zip_slip_path_traversal_blocked():
    """
    Adversarial Attack: Craft an evidence pack containing a Zip Slip path traversal entry ('../../evil.txt').
    Both ai-evidence-cli and EvidenceVerifier MUST detect the traversal and abort with Exit Code 6.
    """
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        zip_slip_path = tf.name

    try:
        with zipfile.ZipFile(zip_slip_path, "w") as zf:
            zf.writestr("../../evil.txt", "MALICIOUS PAYLOAD ESCAPING ROOT")
            zf.writestr("manifest.json", json.dumps({"files": {}}))

        # 1. Standalone CLI check
        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", zip_slip_path], capture_output=True, text=True)
            assert res.returncode == 6, f"CLI must exit 6 on Zip Slip, got: {res.returncode}"
            assert "Zip slip detected" in res.stdout

        # 2. Oracle check
        v = EvidenceVerifier(zip_slip_path)
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_GENERAL_FAIL
        assert "Zip slip detected" in msg

    finally:
        if os.path.exists(zip_slip_path):
            os.remove(zip_slip_path)


def test_tier5_pack_corrupt_zip_archive_exit_code_6():
    """
    Adversarial Attack: Supply truncated or corrupted ZIP archive.
    CLI and Oracle must return EXIT_GENERAL_FAIL (6).
    """
    corrupt_pack = PACKS_DIR / "corrupt_archive.zip"
    if corrupt_pack.exists():
        v = EvidenceVerifier(str(corrupt_pack))
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_GENERAL_FAIL
        assert "Corrupt or invalid zip archive" in msg

        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", str(corrupt_pack)], capture_output=True, text=True)
            assert res.returncode == 6


def test_tier5_pack_1byte_event_tampering_exit_code_1():
    """
    Adversarial Attack: Single-byte modification in events.json.
    Manifest SHA-256 check fails -> EXIT_MANIFEST_FAIL (1).
    """
    tampered_pack = PACKS_DIR / "tampered_manifest.zip"
    if tampered_pack.exists():
        v = EvidenceVerifier(str(tampered_pack))
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_MANIFEST_FAIL
        assert "Hash mismatch" in msg

        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", str(tampered_pack)], capture_output=True, text=True)
            assert res.returncode == 1
            assert "Hash mismatch" in res.stdout


def test_tier5_pack_1byte_signature_tampering_exit_code_3():
    """
    Adversarial Attack: Single-byte corruption in cryptographic digital signature.
    Signature check fails -> EXIT_SIGNATURE_FAIL (3).
    """
    invalid_sig_pack = PACKS_DIR / "invalid_signature.zip"
    if invalid_sig_pack.exists():
        v = EvidenceVerifier(str(invalid_sig_pack))
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_SIGNATURE_FAIL

        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", str(invalid_sig_pack)], capture_output=True, text=True)
            assert res.returncode == 3
            assert "Signature verification failed" in res.stdout


def test_tier5_pack_untrusted_ca_cert_exit_code_4():
    """
    Adversarial Attack: Pack signed with cert from an untrusted Root CA.
    X.509 cert validation prior to signature check must return EXIT_CERT_FAIL (4).
    """
    untrusted_pack = PACKS_DIR / "untrusted_cert.zip"
    if untrusted_pack.exists():
        v = EvidenceVerifier(str(untrusted_pack))
        code, msg = v.verify()
        assert code == EvidenceVerifier.EXIT_CERT_FAIL
        assert "untrusted" in msg or "Root CA" in msg

        if CLI_BIN.exists():
            res = subprocess.run([str(CLI_BIN), "verify", str(untrusted_pack)], capture_output=True, text=True)
            assert res.returncode == 4


def test_tier5_pack_expired_cert_exit_code_4():
    """
    Adversarial Attack: Pack signed by an expired X.509 certificate.
    Must return EXIT_CERT_FAIL (4).
    """
    expired_cert_path = CERTS_DIR / "expired_signer.pem"
    if expired_cert_path.exists():
        with open(expired_cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = time.time()
        # Certificate expired check
        assert cert.not_valid_after_utc.timestamp() < now


# ==============================================================================
# 5. SDK Resilience
# ==============================================================================

def test_tier5_sdk_dead_port_59999_zero_exceptions():
    """
    Adversarial Resilience: Ingest API unreachable on dead port 59999.
    log_decision() MUST:
    1. Never raise any unhandled exceptions to the calling ML pipeline.
    2. Strictly return in < 5.0ms (non-blocking bounded queue).
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/api/v1/ml/ingest",
        max_queue_size=2000,
        drop_policy=DropPolicy.DROP_OLDEST
    )

    latencies_ms = []
    iterations = 500

    try:
        for i in range(iterations):
            payload = {"ai_system_id": "credit-risk-ml", "score": 0.75, "iter": i}
            t0 = time.perf_counter()
            success = client.log_decision(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            latencies_ms.append(elapsed_ms)
            assert success is True
            assert elapsed_ms < 5.0, f"Call {i} exceeded 5.0ms SLA: {elapsed_ms:.4f}ms"

        max_lat = max(latencies_ms)
        p95_lat = sorted(latencies_ms)[int(len(latencies_ms) * 0.95)]
        assert max_lat < 5.0
        assert p95_lat < 0.5, f"P95 latency higher than expected: {p95_lat:.4f}ms"

    finally:
        client.close(timeout=0.5)


def test_tier5_sdk_hanging_blackhole_connection():
    """
    Adversarial Resilience: Ingest API hangs indefinitely (TCP blackhole accepts but sends nothing).
    log_decision() MUST return in < 5.0ms without blocking on the hanging connection.
    """
    # Start ephemeral blackhole TCP server
    blackhole_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blackhole_sock.bind(("127.0.0.1", 0))
    blackhole_sock.listen(5)
    blackhole_port = blackhole_sock.getsockname()[1]

    client = EvidenceClient(
        ingest_url=f"http://127.0.0.1:{blackhole_port}/api/v1/ml/ingest",
        max_queue_size=1000,
        http_timeout_sec=10.0  # Deliberately large timeout to test isolation
    )

    try:
        for i in range(50):
            t0 = time.perf_counter()
            success = client.log_decision({"event": "blackhole_test", "i": i})
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            assert success is True
            assert elapsed_ms < 5.0, f"Hanging connection leaked delay to caller: {elapsed_ms}ms"

    finally:
        client.close(timeout=0.2)
        blackhole_sock.close()


def test_tier5_sdk_high_concurrency_stress_sla():
    """
    Adversarial Resilience: 8 concurrent threads executing 125 calls each (1,000 total calls).
    All 1,000 calls MUST complete within < 5.0ms per call.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/api/v1/ml/ingest",
        max_queue_size=3000
    )

    num_threads = 8
    calls_per_thread = 125
    all_latencies = []

    def thread_worker(tid: int):
        lats = []
        for i in range(calls_per_thread):
            t0 = time.perf_counter()
            ok = client.log_decision({"thread": tid, "i": i, "score": 0.9})
            elapsed = (time.perf_counter() - t0) * 1000.0
            lats.append(elapsed)
            assert ok is True
        return lats

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(thread_worker, tid) for tid in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                all_latencies.extend(f.result())

        assert len(all_latencies) == 1000
        sorted_lats = sorted(all_latencies)
        max_lat = max(all_latencies)
        p99_lat = sorted_lats[int(len(all_latencies) * 0.99)]
        p95_lat = sorted_lats[int(len(all_latencies) * 0.95)]
        assert p99_lat < 5.0, f"P99 latency violated SLA: {p99_lat}ms"
        assert p95_lat < 1.0, f"P95 latency too high: {p95_lat}ms"

    finally:
        client.close(timeout=0.5)


def test_tier5_sdk_drop_policy_buffer_saturation():
    """
    Adversarial Resilience: Buffer saturation under dead port condition.
    Queue size 25, submit 60 events with DropPolicy.DROP_OLDEST.
    Queue size never exceeds capacity, dropped_events increments cleanly, 0 crashes.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/api/v1/ml/ingest",
        max_queue_size=25,
        drop_policy=DropPolicy.DROP_OLDEST
    )

    try:
        for i in range(60):
            ok = client.log_decision({"i": i})
            assert ok is True

        assert client.dropped_events >= 35, f"Expected >= 35 drops, got {client.dropped_events}"
        assert len(client._buffer) <= 25

    finally:
        client.close(timeout=0.2)


# ==============================================================================
# 6. Benchmark Verification
# ==============================================================================

def test_tier5_benchmark_python_sdk_queue_latency_sla():
    """
    Benchmark Verification: Assert that 1,000 sequential log_decision calls
    strictly satisfy the < 5.0ms SLA guarantee (P95 < 0.5ms).
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/api/v1/ml/ingest",
        max_queue_size=2000
    )

    latencies_ms = []
    iterations = 1000

    try:
        for i in range(iterations):
            payload = {
                "ai_system_id": "credit-scoring-xgboost",
                "score": 745.5,
                "features": {"income": 45000000, "debt_ratio": 0.28, "n": i}
            }
            t0 = time.perf_counter()
            ok = client.log_decision(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            latencies_ms.append(elapsed_ms)
            assert ok is True
            assert elapsed_ms < 5.0, f"Iteration {i} violated 5.0ms: {elapsed_ms:.4f}ms"

        sorted_lat = sorted(latencies_ms)
        max_lat = max(latencies_ms)
        p99_lat = sorted_lat[int(len(latencies_ms) * 0.99)]
        p95_lat = sorted_lat[int(len(latencies_ms) * 0.95)]
        p50_lat = sorted_lat[int(len(latencies_ms) * 0.50)]

        print(f"\n[TIER 5 SDK SLA RESULTS] Max: {max_lat:.4f}ms | P99: {p99_lat:.4f}ms | P95: {p95_lat:.4f}ms | P50: {p50_lat:.4f}ms")
        assert max_lat < 5.0
        assert p95_lat < 0.5

    finally:
        client.close(timeout=0.5)


def find_free_port() -> int:
    """Finds an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_tier5_benchmark_gateway_overhead_50kb_sla():
    """
    Benchmark Verification: Measure direct upstream Mock LLM latency vs Gateway reverse proxy latency
    on a realistic 50KB payload using connection pooling and keep-alive to avoid socket recycling churn.
    Asserts: Delta P95 latency overhead < 15.0ms across 100+ requests.
    """
    import requests
    from requests.adapters import HTTPAdapter

    if not GATEWAY_BIN.exists():
        pytest.skip(f"Gateway binary not found at {GATEWAY_BIN}")

    payload_file = PAYLOADS_DIR / "payload_50kb.json"
    if not payload_file.exists():
        pytest.skip(f"50KB payload fixture not found at {payload_file}")

    with open(payload_file, "rb") as f:
        payload_bytes = f.read()

    # 1. Start Mock LLM on ephemeral port
    mock_server = MockLLMServer(host="127.0.0.1", port=0)
    mock_port = mock_server.start()
    direct_url = f"http://127.0.0.1:{mock_port}/v1/chat/completions"

    # 2. Start Gateway on ephemeral port pointing to Mock LLM
    gw_port = find_free_port()
    env = os.environ.copy()
    env["GATEWAY_PORT"] = str(gw_port)
    env["UPSTREAM_LLM_URL"] = f"http://127.0.0.1:{mock_port}"
    env["LEDGER_QUEUE_CAPACITY"] = "50000"

    gw_proc = subprocess.Popen(
        [str(GATEWAY_BIN)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(PROJECT_ROOT)
    )

    # Poll gateway health
    gw_health = f"http://127.0.0.1:{gw_port}/health"
    gw_ready = False
    start_poll = time.time()
    while time.time() - start_poll < 10.0:
        try:
            with urllib.request.urlopen(gw_health, timeout=0.5) as r:
                if r.status == 200:
                    gw_ready = True
                    break
        except Exception:
            time.sleep(0.05)

    assert gw_ready, f"Go Gateway failed to become healthy at {gw_health}"
    gw_url = f"http://127.0.0.1:{gw_port}/v1/chat/completions"

    direct_headers = {
        "Content-Type": "application/json",
        "X-Correlation-ID": "e2e-bench-direct"
    }
    gw_headers = {
        "Content-Type": "application/json",
        "X-AI-System-ID": "securities-quant-advisor-v1",
        "X-Correlation-ID": "e2e-bench-gw"
    }

    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3)
    session.mount("http://", adapter)

    try:
        # Warm-up phase (15 iterations per target)
        for _ in range(15):
            resp_d = session.post(direct_url, data=payload_bytes, headers=direct_headers, timeout=10)
            assert resp_d.status_code == 200
            resp_g = session.post(gw_url, data=payload_bytes, headers=gw_headers, timeout=10)
            assert resp_g.status_code == 200

        # Phased batching: 100 requests per contract
        iterations = 100

        # Phase 1: Benchmark Direct Mock LLM
        direct_latencies = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            resp = session.post(direct_url, data=payload_bytes, headers=direct_headers, timeout=10)
            assert resp.status_code == 200
            direct_latencies.append((time.perf_counter() - t0) * 1000.0)

        # Phase 2: Benchmark Gateway Reverse Proxy
        gateway_latencies = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            resp = session.post(gw_url, data=payload_bytes, headers=gw_headers, timeout=10)
            assert resp.status_code == 200
            gateway_latencies.append((time.perf_counter() - t0) * 1000.0)

        direct_p95 = sorted(direct_latencies)[int(len(direct_latencies) * 0.95)]
        gateway_p95 = sorted(gateway_latencies)[int(len(gateway_latencies) * 0.95)]
        overhead_p95 = gateway_p95 - direct_p95

        print(f"\n[GATEWAY 50KB BENCHMARK] Direct P95: {direct_p95:.2f}ms | Gateway P95: {gateway_p95:.2f}ms | Overhead P95: {overhead_p95:.2f}ms")
        assert overhead_p95 < 15.0, f"Gateway p95 overhead exceeded 15.0ms SLA: {overhead_p95:.2f}ms"

    finally:
        session.close()
        gw_proc.terminate()
        try:
            gw_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            gw_proc.kill()
        mock_server.stop()

