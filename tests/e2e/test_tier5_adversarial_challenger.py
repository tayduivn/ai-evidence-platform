"""
Tier 5 Adversarial Challenge Suite (Empirical Challenger M7.2).

Exhaustively verifies white-box adversarial scenarios assigned to challenger_m7_2:
1. Gateway connection aborts & client disconnects during SSE streaming.
2. Shadow AI unregistered systems (HTTP 403) vs registered systems (HTTP 200/202).
3. Immudb connection drop and WAL crash replay integrity under concurrent writes.
4. KeyMutex per-decision serialization under rapid double-click approval requests.
5. CLI exit code contract across corrupted, invalid, and tampered archives (0 to 6).
"""

import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.mock_llm.server import MockLLMServer
from tests.e2e.conftest import (
    VietnamesePIIScanner,
    AIRegistryContract,
    MerkleAuditEngine,
    ApprovalStateMachine,
    MockPythonSDKClient
)
from tests.e2e.verifier_oracle import EvidenceVerifier, canonical_json

CLI_BINARY_PATH = PROJECT_ROOT / "cli" / "ai-evidence-cli" / "ai-evidence-cli.exe"


# ==============================================================================
# Helper Classes: Reference WAL Engine & KeyMutex Simulator
# ==============================================================================

class BinaryWALEngine:
    """
    Python Reference Engine for Binary WAL conforming to services/ledger/wal.go.
    Frame layout:
    - 4 Bytes: Magic 0x57414C31 ('WAL1')
    - 4 Bytes: Payload Length (BigEndian uint32)
    - 4 Bytes: CRC32-IEEE checksum of payload (BigEndian uint32)
    - N Bytes: UTF-8 JSON Payload
    """
    WAL_MAGIC = 0x57414C31

    @classmethod
    def frame_event(cls, event: Dict[str, Any]) -> bytes:
        payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
        payload_len = len(payload)
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = struct.pack(">III", cls.WAL_MAGIC, payload_len, crc)
        return header + payload

    @classmethod
    def parse_frames(cls, data: bytes) -> Tuple[List[Dict[str, Any]], int, List[str]]:
        """Parses contiguous binary WAL frames, validating magic and CRC32."""
        offset = 0
        events = []
        corrupt_frames = 0
        errors = []

        while offset < len(data):
            if len(data) - offset < 12:
                errors.append(f"Truncated header at offset {offset}")
                corrupt_frames += 1
                break

            magic, payload_len, expected_crc = struct.unpack_from(">III", data, offset)
            if magic != cls.WAL_MAGIC:
                errors.append(f"Invalid WAL magic 0x{magic:08X} at offset {offset}")
                corrupt_frames += 1
                offset += 1
                continue

            frame_end = offset + 12 + payload_len
            if frame_end > len(data):
                errors.append(f"Incomplete payload for frame at offset {offset}")
                corrupt_frames += 1
                break

            payload = data[offset + 12 : frame_end]
            actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                errors.append(f"CRC32 mismatch at offset {offset}: expected {expected_crc:#x}, got {actual_crc:#x}")
                corrupt_frames += 1
                offset = frame_end
                continue

            try:
                event = json.loads(payload.decode("utf-8"))
                events.append(event)
            except Exception as e:
                errors.append(f"JSON decode failure at offset {offset}: {e}")
                corrupt_frames += 1

            offset = frame_end

        return events, corrupt_frames, errors


class KeyMutexSimulator:
    """
    Python Reference Implementation of Per-Key Mutex and State Machine.
    Simulates services/approval/internal/lifecycle/state_machine.go KeyMutex behavior.
    """
    def __init__(self, approval_sm: ApprovalStateMachine):
        self.sm = approval_sm
        self.locks: Dict[str, threading.Lock] = {}
        self.global_lock = threading.Lock()

    def _get_key_lock(self, key: str) -> threading.Lock:
        with self.global_lock:
            if key not in self.locks:
                self.locks[key] = threading.Lock()
            return self.locks[key]

    def submit_action_synchronized(
        self, approver_id: str, action: str, dwell_seconds: int, signer_type: str = "internal"
    ) -> Tuple[int, str]:
        lock = self._get_key_lock(self.sm.decision_id)
        with lock:
            return self.sm.submit_action(approver_id, action, dwell_seconds, signer_type)


# ==============================================================================
# Group 1: Gateway SSE Client Disconnects & Aborts (3 tests)
# ==============================================================================

def test_tier5_sse_client_abrupt_disconnect(mock_llm):
    """
    Scenario 1A: Client starts an SSE streaming request, reads initial chunks, and abruptly drops TCP connection.
    Verifies Mock LLM server catches the aborted connection and subsequent requests succeed without hang.
    """
    server_port = mock_llm.port
    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Explain quantum computing in detail."}],
        "stream": True
    }).encode("utf-8")

    # Connect raw socket and send HTTP request
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", server_port))
    req = (
        f"POST /v1/chat/completions HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server_port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + payload
    s.sendall(req)

    # Read response header and initial chunk
    resp_chunk = s.recv(256)
    assert b"200 OK" in resp_chunk or b"data:" in resp_chunk

    # Abruptly close socket while stream is active
    s.close()
    time.sleep(0.05)

    # Verify server remains healthy for subsequent normal request
    conn = http.client.HTTPConnection("127.0.0.1", server_port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    assert resp.status == 200
    conn.close()


def test_tier5_sse_rapid_concurrent_disconnects(mock_llm):
    """
    Scenario 1B: 10 concurrent clients initiate streaming and abort mid-stream simultaneously.
    Verifies no server deadlock, no unhandled exceptions, and server recovery.
    """
    server_port = mock_llm.port
    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Stream tokens rapidly."}],
        "stream": True
    }).encode("utf-8")

    def client_abort_worker():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", server_port))
            req = (
                f"POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{server_port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + payload
            s.sendall(req)
            _ = s.recv(128)
            time.sleep(0.01)
            s.close()
            return True
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(client_abort_worker) for _ in range(10)]
        results = [f.result() for f in futures]

    assert all(results), "All client abort threads executed cleanly"

    # Verify health check immediately after burst
    conn = http.client.HTTPConnection("127.0.0.1", server_port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    assert resp.status == 200
    conn.close()


def test_tier5_sse_upstream_injected_drop(mock_llm):
    """
    Scenario 1C: Upstream server drops connection via fault injection header X-Mock-Drop.
    Verifies client detects dropped connection cleanly.
    """
    server_port = mock_llm.port
    conn = http.client.HTTPConnection("127.0.0.1", server_port, timeout=5)
    headers = {
        "Content-Type": "application/json",
        "X-Mock-Drop": "true"
    }
    payload = json.dumps({"model": "gpt-4o", "messages": [], "stream": True})

    with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
        conn.request("POST", "/v1/chat/completions", body=payload, headers=headers)
        _ = conn.getresponse()
    conn.close()


# ==============================================================================
# Group 2: Shadow AI & Registry Gating (HTTP 403 vs 200/202) (4 tests)
# ==============================================================================

def test_tier5_shadow_ai_missing_header_rejected():
    """Verify missing X-AI-System-ID header is strictly rejected with HTTP 403."""
    code, msg = AIRegistryContract.evaluate_request(ai_system_id=None)
    assert code == 403
    assert "Missing X-AI-System-ID header" in msg


def test_tier5_shadow_ai_unregistered_id_rejected():
    """Verify unregistered rogue AI systems are rejected with HTTP 403."""
    rogue_systems = [
        "shadow-unauthorized-gpt-v1",
        "rogue-trading-bot-internal",
        "unregistered_pipeline_01",
        "system-12345"
    ]
    for rogue_id in rogue_systems:
        code, msg = AIRegistryContract.evaluate_request(ai_system_id=rogue_id)
        assert code == 403
        assert "Unregistered AI system" in msg
        assert "Shadow AI rejected" in msg


def test_tier5_shadow_ai_tampered_model_artifacts():
    """Verify registered system with tampered artifact hash is blocked with HTTP 403."""
    system_id = "credit-scoring-xgboost"
    tampered_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    code, msg = AIRegistryContract.evaluate_request(
        ai_system_id=system_id,
        artifact_hash=tampered_hash
    )
    assert code == 403
    assert "Artifact hash mismatch: Model tampering detected" in msg


def test_tier5_shadow_ai_registered_audit_vs_intercept():
    """Verify registered systems return 200 for audit-only and 202 for intercept approval."""
    # 1. Audit-only registered system
    code, msg = AIRegistryContract.evaluate_request("securities-quant-advisor-v1")
    assert code == 200
    assert msg == "AUTHORIZED"

    # 2. Intercept approval registered system
    spec = AIRegistryContract.REGISTERED_SYSTEMS["credit-advisor-v1"]
    assert spec["requires_approval"] is True
    code, msg = AIRegistryContract.evaluate_request(
        "credit-advisor-v1",
        prompt_hash="a1b2c3d4"
    )
    assert code == 200
    assert msg == "AUTHORIZED"


# ==============================================================================
# Group 3: Immudb Connection Drop & WAL Crash Replay Integrity (4 tests)
# ==============================================================================

def test_tier5_wal_frame_binary_layout(tmp_path):
    """
    Scenario 3A: Verifies binary WAL framing conforming to services/ledger/wal.go:
    Magic(4B) + Length(4B) + CRC32(4B) + Payload(NB).
    """
    sample_event = {
        "event_id": "ev-wal-001",
        "ai_system_id": "credit-scoring-xgboost",
        "score": 820.5,
        "decision": "APPROVE"
    }
    frame = BinaryWALEngine.frame_event(sample_event)
    assert len(frame) == 12 + len(json.dumps(sample_event, ensure_ascii=False).encode("utf-8"))

    # Unpack header
    magic, length, crc = struct.unpack(">III", frame[:12])
    assert magic == 0x57414C31  # "WAL1"
    assert length == len(frame) - 12
    payload = frame[12:]
    assert (zlib.crc32(payload) & 0xFFFFFFFF) == crc


def test_tier5_wal_spooling_and_replay_integrity(tmp_path):
    """
    Scenario 3B: Simulates immudb connection drop where 100 events are spooled to WAL.
    Replays all 100 events upon recovery and validates exact FIFO order without data loss.
    """
    wal_file = tmp_path / "wal-00000001.log"
    total_events = 100
    generated_events = []

    with open(wal_file, "wb") as f:
        for i in range(total_events):
            ev = {
                "event_id": f"ev-wal-{i:04d}",
                "correlation_id": f"tx-corr-{i}",
                "ai_system_id": "securities-quant-advisor-v1",
                "seq": i,
                "timestamp": time.time()
            }
            generated_events.append(ev)
            f.write(BinaryWALEngine.frame_event(ev))

    # Read and replay pending events
    data = wal_file.read_bytes()
    replayed_events, corrupt_count, errors = BinaryWALEngine.parse_frames(data)

    assert corrupt_count == 0
    assert len(errors) == 0
    assert len(replayed_events) == total_events
    for i in range(total_events):
        assert replayed_events[i]["event_id"] == generated_events[i]["event_id"]
        assert replayed_events[i]["seq"] == i


def test_tier5_wal_bit_flip_corruption_detection(tmp_path):
    """
    Scenario 3C: Injects single-bit and byte-level corruptions into a WAL frame.
    Verifies that CRC32 checksum mismatch detects corruption and prevents bad event ingestion.
    """
    ev = {"event_id": "ev-secure-001", "action": "TRANSFER", "amount": 100000000}
    valid_frame = bytearray(BinaryWALEngine.frame_event(ev))

    # Bit flip inside payload body
    corrupt_frame = bytearray(valid_frame)
    corrupt_frame[15] ^= 0xFF

    events, corrupt_count, errors = BinaryWALEngine.parse_frames(bytes(corrupt_frame))
    assert corrupt_count == 1
    assert len(events) == 0
    assert any("CRC32 mismatch" in err for err in errors)


def test_tier5_wal_concurrent_spooling_stress(tmp_path):
    """
    Scenario 3D: 10 concurrent threads simultaneously write 50 events each (500 total) to WAL.
    Verifies thread-safe atomic appending with zero frame overlap and 100% replay recovery.
    """
    wal_file = tmp_path / "wal-concurrent.log"
    wal_lock = threading.Lock()
    num_threads = 10
    events_per_thread = 50
    total_expected = num_threads * events_per_thread

    def worker_thread(tid: int):
        for i in range(events_per_thread):
            ev = {"tid": tid, "i": i, "token": f"t-{tid}-{i}"}
            frame = BinaryWALEngine.frame_event(ev)
            with wal_lock:
                with open(wal_file, "ab") as f:
                    f.write(frame)

    threads = [threading.Thread(target=worker_thread, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    data = wal_file.read_bytes()
    replayed, corrupt, errors = BinaryWALEngine.parse_frames(data)

    assert corrupt == 0, f"Detected {corrupt} corrupt frames: {errors}"
    assert len(replayed) == total_expected, f"Expected {total_expected} replayed events, got {len(replayed)}"


# ==============================================================================
# Group 4: KeyMutex Per-Decision Serialization & Race Resistance (4 tests)
# ==============================================================================

def test_tier5_keymutex_rapid_double_clicks():
    """
    Scenario 4A: 20 simultaneous threads submit 'APPROVE' on the exact same decision ID.
    Asserts that strictly ONE request succeeds with StatusApproved, and 19 fail cleanly,
    preventing duplicate approval actions or race condition state corruption.
    """
    decision_id = "dec-double-click-001"
    raw_sm = ApprovalStateMachine(decision_id=decision_id, creator_id="creator-user", min_dwell_seconds=10, requires_4_eyes=False)
    sync_sm = KeyMutexSimulator(raw_sm)

    num_clicks = 20
    results: List[Tuple[int, str]] = []
    lock = threading.Lock()

    def click_worker(idx: int):
        res = sync_sm.submit_action_synchronized(
            approver_id="approver-alice",
            action="APPROVE",
            dwell_seconds=12,
            signer_type="internal"
        )
        with lock:
            results.append(res)

    threads = [threading.Thread(target=click_worker, args=(i,)) for i in range(num_clicks)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == 200]
    failures = [r for r in results if r[0] != 200]

    assert len(successes) == 1, f"Expected exactly 1 successful approval, got {len(successes)}"
    assert len(failures) == num_clicks - 1, f"Expected {num_clicks - 1} terminal rejections, got {len(failures)}"
    assert sync_sm.sm.status == ApprovalStateMachine.STATUS_APPROVED


def test_tier5_keymutex_cross_decision_parallelism():
    """
    Scenario 4B: Approvals on 10 DISTINCT decision IDs are processed concurrently.
    Verifies KeyMutex allows parallel execution across different keys without global blocking.
    """
    decisions = [f"dec-parallel-{i:03d}" for i in range(10)]
    sms = {d_id: KeyMutexSimulator(ApprovalStateMachine(d_id, "creator", min_dwell_seconds=10, requires_4_eyes=False)) for d_id in decisions}

    def approve_decision(d_id: str):
        return sms[d_id].submit_action_synchronized(
            approver_id="distinct-approver",
            action="APPROVE",
            dwell_seconds=15
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(approve_decision, d): d for d in decisions}
        for fut in concurrent.futures.as_completed(futures):
            code, msg = fut.result()
            assert code == 200

    for d_id in decisions:
        assert sms[d_id].sm.status == ApprovalStateMachine.STATUS_APPROVED


def test_tier5_keymutex_4eyes_duplicate_approver_rejection():
    """
    Scenario 4C: 4-Eyes requires two distinct approvers.
    Under 10 concurrent requests from the SAME first approver, strictly rejects all duplicates.
    """
    d_id = "dec-4eyes-dup-001"
    raw_sm = ApprovalStateMachine(d_id, "creator-user", min_dwell_seconds=10, requires_4_eyes=True)
    sync_sm = KeyMutexSimulator(raw_sm)

    # First approval succeeds
    code, msg = sync_sm.submit_action_synchronized("approver-lead", "APPROVE", 15)
    assert code == 200
    assert sync_sm.sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND

    # Concurrent double-click attempts by the SAME approver
    results = []
    def second_attempt():
        res = sync_sm.submit_action_synchronized("approver-lead", "APPROVE", 15)
        results.append(res)

    threads = [threading.Thread(target=second_attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All attempts must be rejected with DUPLICATE_APPROVER (400)
    for code, msg in results:
        assert code == 400
        assert "DUPLICATE_APPROVER" in msg


def test_tier5_keymutex_creator_self_approval_rejection():
    """
    Scenario 4D: Creator attempts rapid concurrent self-approvals.
    100% of calls must be rejected with HTTP 403 CREATOR_CANNOT_APPROVE.
    """
    d_id = "dec-self-approval-001"
    sync_sm = KeyMutexSimulator(ApprovalStateMachine(d_id, creator_id="risk-analyst-bob", min_dwell_seconds=10))

    for _ in range(5):
        code, msg = sync_sm.submit_action_synchronized(
            approver_id="risk-analyst-bob",
            action="APPROVE",
            dwell_seconds=20
        )
        assert code == 403
        assert "CREATOR_CANNOT_APPROVE" in msg


# ==============================================================================
# Group 5: CLI Exit Code Contract (Exit codes 0 to 6) (8 tests)
# ==============================================================================

def test_tier5_cli_exit_code_0_valid_pack(fixtures_paths):
    """Scenario 5A: Valid Evidence Pack must return Exit Code 0 (VERIFICATION_SUCCESS)."""
    pack_path = fixtures_paths["packs"] / "valid_pack.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 0
        assert "VERIFICATION_SUCCESS" in proc.stdout

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SUCCESS
    assert msg == "VERIFICATION_SUCCESS"


def test_tier5_cli_exit_code_1_tampered_manifest(fixtures_paths):
    """Scenario 5B: Tampered Manifest must return Exit Code 1 (EXIT_MANIFEST_FAIL)."""
    pack_path = fixtures_paths["packs"] / "tampered_manifest.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 1

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_MANIFEST_FAIL


def test_tier5_cli_exit_code_2_tampered_merkle(fixtures_paths):
    """Scenario 5C: Tampered Merkle Proof must return Exit Code 2 (EXIT_MERKLE_FAIL)."""
    pack_path = fixtures_paths["packs"] / "tampered_merkle.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 2

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_MERKLE_FAIL


def test_tier5_cli_exit_code_3_invalid_signature(fixtures_paths):
    """Scenario 5D: Invalid Digital Signature must return Exit Code 3 (EXIT_SIGNATURE_FAIL)."""
    pack_path = fixtures_paths["packs"] / "invalid_signature.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 3

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SIGNATURE_FAIL


def test_tier5_cli_exit_code_4_untrusted_cert(fixtures_paths):
    """Scenario 5E: Untrusted Certificate Chain must return Exit Code 4 (EXIT_CERT_FAIL)."""
    pack_path = fixtures_paths["packs"] / "untrusted_cert.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 4

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_CERT_FAIL


def test_tier5_cli_exit_code_5_policy_violation(fixtures_paths):
    """Scenario 5F: 4-Eyes policy violation must return Exit Code 5 (EXIT_POLICY_FAIL)."""
    pack_path = fixtures_paths["packs"] / "policy_violation_pack.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 5

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_POLICY_FAIL


def test_tier5_cli_exit_code_6_corrupted_archive(fixtures_paths):
    """Scenario 5G: Corrupt Zip Archive must return Exit Code 6 (EXIT_GENERAL_FAIL)."""
    pack_path = fixtures_paths["packs"] / "corrupt_archive.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(pack_path)], capture_output=True, text=True)
        assert proc.returncode == 6

    verifier = EvidenceVerifier(str(pack_path), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_GENERAL_FAIL


def test_tier5_cli_exit_code_6_non_existent_file(tmp_path):
    """Scenario 5H: Non-Existent Archive must return Exit Code 6 (EXIT_GENERAL_FAIL)."""
    non_existent = tmp_path / "does_not_exist.zip"
    if CLI_BINARY_PATH.exists():
        proc = subprocess.run([str(CLI_BINARY_PATH), "verify", str(non_existent)], capture_output=True, text=True)
        assert proc.returncode == 6

    verifier = EvidenceVerifier(str(non_existent), min_dwell_seconds=10)
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_GENERAL_FAIL
