"""Adversarial stress and empirical challenge suite for Python SDK (ai_evidence_sdk).

Challenger Mandate:
1. Strict latency SLA benchmark (< 5.0ms across 5,000+ rapid calls and multi-threaded bursts).
2. Network fault injection (dead port 59999, hanging socket, 500 server error): assert zero exceptions leaked.
3. Queue saturation and drop policy verification (DROP_OLDEST, DROP_NEWEST).
4. Approval workflow dict indexing and 4-Eyes polling continuation across intermediate states.
5. Webhook HMAC-SHA256 tamper rejection & security probing.
"""

import concurrent.futures
import hashlib
import hmac
import http.client
import json
import socket
import threading
import time
import urllib.request
from typing import Any, Dict, List
import pytest

from ai_evidence_sdk.approval.handle import ApprovalHandle
from ai_evidence_sdk.approval.result import ApprovalResult
from ai_evidence_sdk.approval.states import ApprovalStatus
from ai_evidence_sdk.approval.webhook import WebhookReceiver, verify_webhook_signature
from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.models import DropPolicy


# ==============================================================================
# Helper Fixtures & Mock Utilities
# ==============================================================================

class HangingServer:
    """Raw TCP socket server that accepts connections but never responds or closes."""
    def __init__(self, host="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.sock.listen(50)
        self.host, self.port = self.sock.getsockname()
        self.running = True
        self.client_sockets = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                client, _ = self.sock.accept()
                self.client_sockets.append(client)
                # Intentionally hang: never read or write anything
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self.running = False
        for s in self.client_sockets:
            try:
                s.close()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)


# ==============================================================================
# 1. Strict Latency SLA Benchmark (< 5.0ms across 5,000+ calls & multi-threading)
# ==============================================================================

def test_sla_benchmark_5000_sequential_calls():
    """
    Stress-test: 5,000 sequential rapid calls to log_decision().
    Assert 100% of calls complete in < 5.0ms.
    Record min, p50, p95, p99, and max latencies.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=20000,
    )
    iterations = 5000
    latencies_ms = []

    try:
        for i in range(iterations):
            payload = {
                "ai_system_id": "adversarial-seq-benchmark",
                "score": 0.99,
                "features": {"iter": i, "token_count": 42},
            }
            t0 = time.perf_counter()
            accepted = client.log_decision(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

            assert accepted is True, f"Call {i} was unexpectedly rejected"
            assert elapsed_ms < 5.0, f"SLA VIOLATION at call {i}: {elapsed_ms:.4f}ms >= 5.0ms"

        sorted_lat = sorted(latencies_ms)
        min_lat = sorted_lat[0]
        max_lat = sorted_lat[-1]
        p50_lat = sorted_lat[int(iterations * 0.50)]
        p95_lat = sorted_lat[int(iterations * 0.95)]
        p99_lat = sorted_lat[int(iterations * 0.99)]
        mean_lat = sum(latencies_ms) / iterations

        print(
            f"\n[CHALLENGER SLA 5K SEQUENTIAL] Total: {iterations} | "
            f"Min: {min_lat:.4f}ms | P50: {p50_lat:.4f}ms | P95: {p95_lat:.4f}ms | "
            f"P99: {p99_lat:.4f}ms | Max: {max_lat:.4f}ms | Mean: {mean_lat:.4f}ms"
        )

        assert max_lat < 5.0, f"Max latency SLA violated: {max_lat:.4f}ms"
        assert p99_lat < 0.25, f"P99 latency unusually elevated: {p99_lat:.4f}ms"
    finally:
        client.close(timeout=0.2)


def test_sla_benchmark_multithreaded_burst_10_threads():
    """
    Stress-test: 10 concurrent threads each executing 500 calls (5,000 total calls).
    Assert 100% of concurrent calls complete in < 5.0ms under high thread contention.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=20000,
    )
    num_threads = 10
    calls_per_thread = 500
    total_calls = num_threads * calls_per_thread
    all_latencies_ms = []

    def thread_worker(tid: int) -> List[float]:
        thread_lats = []
        for i in range(calls_per_thread):
            payload = {
                "ai_system_id": "adversarial-mt-benchmark",
                "score": 0.85,
                "features": {"tid": tid, "iter": i},
            }
            t0 = time.perf_counter()
            accepted = client.log_decision(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            thread_lats.append(elapsed_ms)

            assert accepted is True
            assert elapsed_ms < 5.0, f"Thread {tid} call {i} violated SLA: {elapsed_ms:.4f}ms"
        return thread_lats

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(thread_worker, tid) for tid in range(num_threads)]
            for fut in concurrent.futures.as_completed(futures):
                all_latencies_ms.extend(fut.result())

        assert len(all_latencies_ms) == total_calls
        sorted_lat = sorted(all_latencies_ms)
        min_lat = sorted_lat[0]
        max_lat = sorted_lat[-1]
        p50_lat = sorted_lat[int(total_calls * 0.50)]
        p95_lat = sorted_lat[int(total_calls * 0.95)]
        p99_lat = sorted_lat[int(total_calls * 0.99)]

        print(
            f"\n[CHALLENGER SLA 10-THREAD BURST] Total: {total_calls} | "
            f"Min: {min_lat:.4f}ms | P50: {p50_lat:.4f}ms | P95: {p95_lat:.4f}ms | "
            f"P99: {p99_lat:.4f}ms | Max: {max_lat:.4f}ms"
        )

        assert max_lat < 5.0, f"Max latency under thread contention exceeded 5.0ms: {max_lat:.4f}ms"
        assert p99_lat < 0.25, f"P99 latency unusually elevated: {p99_lat:.4f}ms"
    finally:
        client.close(timeout=0.2)


def test_sla_benchmark_10000_heavy_burst():
    """
    Extreme stress-test: 10 concurrent threads x 1,000 calls (10,000 total calls).
    Assert 100% of calls complete in strictly < 5.0ms.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=30000,
    )
    num_threads = 10
    calls_per_thread = 1000
    total_calls = num_threads * calls_per_thread
    all_latencies_ms = []

    def thread_worker(tid: int) -> List[float]:
        thread_lats = []
        for i in range(calls_per_thread):
            t0 = time.perf_counter()
            accepted = client.log_decision({
                "ai_system_id": "heavy-burst",
                "score": 0.92,
                "tid": tid,
                "i": i,
            })
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            thread_lats.append(elapsed_ms)
            assert accepted is True
            assert elapsed_ms < 5.0
        return thread_lats

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(thread_worker, tid) for tid in range(num_threads)]
            for fut in concurrent.futures.as_completed(futures):
                all_latencies_ms.extend(fut.result())

        assert len(all_latencies_ms) == total_calls
        sorted_lat = sorted(all_latencies_ms)
        min_lat = sorted_lat[0]
        max_lat = sorted_lat[-1]
        p50_lat = sorted_lat[int(total_calls * 0.50)]
        p95_lat = sorted_lat[int(total_calls * 0.95)]
        p99_lat = sorted_lat[int(total_calls * 0.99)]

        print(
            f"\n[CHALLENGER SLA 10,000 HEAVY BURST] Total: {total_calls} | "
            f"Min: {min_lat:.4f}ms | P50: {p50_lat:.4f}ms | P95: {p95_lat:.4f}ms | "
            f"P99: {p99_lat:.4f}ms | Max: {max_lat:.4f}ms"
        )

        assert max_lat < 5.0
        assert p99_lat < 0.25
    finally:
        client.close(timeout=0.2)


# ==============================================================================
# 2. Network Fault & Crash Injection (Dead port, Hanging socket, 500 error)
# ==============================================================================

def test_fault_injection_dead_port_59999_zero_exceptions():
    """
    Fault injection: Target port 59999 (completely offline/dead).
    Execute 1,000 rapid calls.
    Assert zero exceptions leak to the caller and 100% complete in < 5.0ms.
    """
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=2000,
    )
    latencies_ms = []

    try:
        for i in range(1000):
            try:
                t0 = time.perf_counter()
                success = client.log_decision({
                    "ai_system_id": "fault-dead-port",
                    "score": 0.5,
                    "payload": f"item-{i}",
                })
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(elapsed_ms)
                assert success is True
                assert elapsed_ms < 5.0
            except Exception as ex:
                pytest.fail(f"log_decision leaked exception on dead port: {type(ex).__name__}: {ex}")

        assert len(latencies_ms) == 1000
        assert max(latencies_ms) < 5.0
    finally:
        client.close(timeout=0.5)


def test_fault_injection_hanging_port_zero_caller_blocking():
    """
    Fault injection: Target a TCP port that accepts connections but hangs indefinitely.
    Assert that caller thread NEVER blocks or waits for network timeouts;
    all log_decision() calls complete in < 5.0ms with zero exceptions.
    """
    hanging_server = HangingServer()
    hanging_url = f"http://127.0.0.1:{hanging_server.port}/api/v1/ml/ingest"

    client = EvidenceClient(
        ingest_url=hanging_url,
        max_queue_size=1000,
        http_timeout_sec=1.0,
    )
    latencies_ms = []

    try:
        for i in range(250):
            try:
                t0 = time.perf_counter()
                success = client.log_decision({
                    "ai_system_id": "fault-hanging-port",
                    "score": 0.77,
                    "i": i,
                })
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(elapsed_ms)
                assert success is True
                assert elapsed_ms < 5.0, f"Caller blocked on hanging socket at call {i}: {elapsed_ms:.4f}ms"
            except Exception as ex:
                pytest.fail(f"Caller thread leaked exception on hanging port: {ex}")

        assert max(latencies_ms) < 5.0
    finally:
        client.close(timeout=0.5)
        hanging_server.stop()


def test_fault_injection_server_500_persistent_flood(mock_gateway):
    """
    Fault injection: Mock Gateway injected to return HTTP 500 on all endpoints.
    Verify that 500 rapid calls remain completely non-blocking (< 5.0ms) and leak 0 exceptions.
    """
    mock_gateway.injected_status = 500

    client = EvidenceClient(
        ingest_url=mock_gateway.ingest_url,
        max_queue_size=2000,
    )

    try:
        for i in range(500):
            t0 = time.perf_counter()
            success = client.log_decision({
                "ai_system_id": "fault-500-flood",
                "score": 0.42,
                "features": {"seq": i},
            })
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            assert success is True
            assert elapsed_ms < 5.0
    finally:
        client.close(timeout=0.5)


# ==============================================================================
# 3. Queue Saturation & Drop Policy Verification (DROP_OLDEST, DROP_NEWEST)
# ==============================================================================

def test_queue_saturation_drop_oldest_strict_ordering():
    """
    Adversarial verification of DROP_OLDEST on BoundedEventQueue:
    Capacity: 10 items.
    Enqueue 100 items: [0, 1, 2, ..., 99].
    Verify:
    - Exactly 90 items dropped (dropped_count == 90).
    - Remaining items in queue are exactly [90, 91, ..., 99] in correct sequence.
    - No deadlocks, memory corruption, or lost newer items.
    """
    buf = BoundedEventQueue(max_size=10, drop_policy=DropPolicy.DROP_OLDEST)

    for i in range(100):
        enqueued = buf.enqueue({"id": i})
        assert enqueued is True

    assert buf.dropped_count == 90
    assert len(buf) == 10
    assert buf.is_full() is True

    # Drain and verify exact sequence of preserved items
    drained = buf.drain_batch(100)
    assert len(drained) == 10
    extracted_ids = [item["id"] for item in drained]
    assert extracted_ids == list(range(90, 100)), f"Unexpected items preserved: {extracted_ids}"
    assert len(buf) == 0


def test_queue_saturation_drop_newest_strict_ordering():
    """
    Adversarial verification of DROP_NEWEST on BoundedEventQueue:
    Capacity: 10 items.
    Enqueue 100 items: [0, 1, 2, ..., 99].
    Verify:
    - First 10 items return True.
    - Subsequent 90 items return False.
    - Exactly 90 items dropped (dropped_count == 90).
    - Preserved items in queue are strictly [0, 1, ..., 9] in correct sequence.
    """
    buf = BoundedEventQueue(max_size=10, drop_policy=DropPolicy.DROP_NEWEST)

    for i in range(100):
        enqueued = buf.enqueue({"id": i})
        if i < 10:
            assert enqueued is True, f"Item {i} should have been accepted"
        else:
            assert enqueued is False, f"Item {i} should have been dropped under DROP_NEWEST"

    assert buf.dropped_count == 90
    assert len(buf) == 10

    drained = buf.drain_batch(100)
    assert len(drained) == 10
    extracted_ids = [item["id"] for item in drained]
    assert extracted_ids == list(range(10)), f"Unexpected items preserved: {extracted_ids}"


def test_client_queue_saturation_drop_policies_dead_endpoint():
    """
    Verify EvidenceClient drop policy behavior end-to-end under simulated offline conditions.
    """
    # 1. DROP_OLDEST
    client_oldest = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=10,
        drop_policy=DropPolicy.DROP_OLDEST,
    )
    try:
        for i in range(100):
            res = client_oldest.log_decision({"i": i})
            assert res is True
        assert client_oldest.dropped_events == 90
        assert len(client_oldest.buffer_queue) == 10
    finally:
        client_oldest.close(timeout=0.2)

    # 2. DROP_NEWEST
    client_newest = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=10,
        drop_policy=DropPolicy.DROP_NEWEST,
    )
    try:
        for i in range(100):
            res = client_newest.log_decision({"i": i})
            if i < 10:
                assert res is True
            else:
                assert res is False
        assert client_newest.dropped_events == 90
        assert len(client_newest.buffer_queue) == 10
    finally:
        client_newest.close(timeout=0.2)


# ==============================================================================
# 4. Approval Workflow Dict Indexing & 4-Eyes Polling Continuation
# ==============================================================================

def test_approval_handle_dict_contract_compatibility(mock_gateway):
    """
    Assert that request_approval() return value supports dict subscripting:
    - res["status"] == "PENDING_APPROVAL"
    - "decision_id" in res
    - "poll_url" in res
    - res.get("correlation_id")
    - len(res), list(iter(res)), res.to_dict()
    Zero regressions for existing tests and consumers expecting a Dict.
    """
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({
            "ai_system_id": "dict-contract-test",
            "score": 0.91,
            "correlation_id": "corr-dict-999",
        })

        assert isinstance(handle, ApprovalHandle)
        # Dict subscripting
        assert handle["status"] == "PENDING_APPROVAL"
        assert "decision_id" in handle
        assert "poll_url" in handle
        assert handle["decision_id"].startswith("dec-ml-")
        assert "/status" in handle["poll_url"]
        assert handle.get("correlation_id") == "corr-dict-999"
        assert handle.get("non_existent_key", "default_val") == "default_val"
        assert len(handle) >= 4
        keys = list(iter(handle))
        assert "status" in keys
        assert "decision_id" in keys

        # to_dict compatibility
        d = handle.to_dict()
        assert isinstance(d, dict)
        assert d["status"] == "PENDING_APPROVAL"
    finally:
        client.close(timeout=0.5)


def test_approval_handle_offline_ticket_dict_contract():
    """
    Verify allow_offline_ticket=True generates a synthetic ticket supporting dict subscripting.
    """
    client = EvidenceClient(ingest_url="http://127.0.0.1:59999/down")
    try:
        ticket = client.request_approval(
            {"ai_system_id": "offline-model", "score": 0.8},
            allow_offline_ticket=True,
        )
        assert ticket["status"] == "PENDING_APPROVAL"
        assert "decision_id" in ticket
        assert "poll_url" in ticket
        assert ticket["decision_id"].startswith("dec-ml-")
    finally:
        client.close(timeout=0.2)


def test_approval_polling_4_eyes_intermediate_continuation(mock_gateway):
    """
    Adversarial verification of 4-Eyes polling:
    Simulate state progression:
    Poll 1: PENDING
    Poll 2: AWAITING_SECOND_APPROVAL (intermediate state)
    Poll 3: AWAITING_SECOND_APPROVAL (intermediate state)
    Poll 4: APPROVED (terminal state)

    Assert:
    - Poller does NOT abort early on intermediate states.
    - Poller completes successfully only upon reaching APPROVED.
    - Approver records include both approvers (4-Eyes principle satisfied).
    """
    mock_gateway.status_sequence = [
        "PENDING",
        "AWAITING_SECOND_APPROVAL",
        "AWAITING_SECOND_APPROVAL",
        "APPROVED",
    ]
    mock_gateway.status_idx = 0
    mock_gateway.approval_history = [
        {
            "approver_id": "approver-alice",
            "role": "RISK_ANALYST",
            "action": "APPROVED",
            "dwell_seconds": 15,
            "signature_hex": "alice_sig_12345",
            "comment": "First signoff verified",
        },
        {
            "approver_id": "approver-bob",
            "role": "CHIEF_RISK_OFFICER",
            "action": "APPROVED",
            "dwell_seconds": 25,
            "signature_hex": "bob_sig_67890",
            "comment": "Final signoff approved",
        },
    ]

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "4eyes-ml", "score": 0.99})

        # Wait with quick poll interval
        result = client.wait_for_decision(
            handle,
            timeout=10.0,
            poll_interval=0.05,
            backoff_multiplier=1.0,
            jitter=False,
        )

        assert isinstance(result, ApprovalResult)
        assert result.is_approved is True
        assert result.status == ApprovalStatus.APPROVED
        assert len(result.approvals) == 2
        assert result.approvals[0].approver_id == "approver-alice"
        assert result.approvals[1].approver_id == "approver-bob"
        assert result.signature_hex == "bob_sig_67890"
    finally:
        client.close(timeout=0.5)


def test_approval_polling_intermediate_rejection(mock_gateway):
    """
    Simulate: PENDING -> AWAITING_SECOND_APPROVAL -> REJECTED.
    Assert poller correctly recognizes terminal rejection after intermediate state.
    """
    mock_gateway.status_sequence = [
        "PENDING",
        "AWAITING_SECOND_APPROVAL",
        "REJECTED",
    ]
    mock_gateway.status_idx = 0
    mock_gateway.rejection_reason = "Rejected by second approver due to policy 402"

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "4eyes-reject-ml", "score": 0.99})

        result = client.wait_for_decision(
            handle,
            timeout=10.0,
            poll_interval=0.05,
            backoff_multiplier=1.0,
            jitter=False,
            raise_on_rejection=False,
        )

        assert result.is_approved is False
        assert result.status == ApprovalStatus.REJECTED
        assert "policy 402" in (result.rejection_reason or "")
    finally:
        client.close(timeout=0.5)


# ==============================================================================
# 5. Webhook HMAC-SHA256 Tamper Rejection & Security Probing
# ==============================================================================

def test_webhook_hmac_tamper_rejection():
    """
    Security probe: Verify HMAC-SHA256 signature verification rejects:
    - Single bit / character tamper in payload
    - Wrong secret key
    - Empty or null signatures
    - Corrupted non-hex signature string
    - Unicode payloads (Vietnamese diacritics)
    """
    secret = "production-super-secret-key-999"
    payload = json.dumps({"event": "APPROVAL_GRANTED", "decision_id": "dec-001"}).encode("utf-8")

    # Compute valid signature
    valid_sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    # 1. Valid signature passes (both raw hex and prefixed)
    assert verify_webhook_signature(payload, valid_sig, secret) is True
    assert verify_webhook_signature(payload, f"sha256={valid_sig}", secret) is True
    assert verify_webhook_signature(payload, f"SHA256={valid_sig.upper()}", secret) is True

    # 2. Tampered payload (single byte modification)
    tampered_payload = json.dumps({"event": "APPROVAL_GRANTED", "decision_id": "dec-002"}).encode("utf-8")
    assert verify_webhook_signature(tampered_payload, valid_sig, secret) is False

    # 3. Wrong secret
    assert verify_webhook_signature(payload, valid_sig, "wrong-secret-key") is False

    # 4. Empty / None signature or secret
    assert verify_webhook_signature(payload, "", secret) is False
    assert verify_webhook_signature(payload, valid_sig, "") is False

    # 5. Corrupted signature strings (invalid hex, truncated, extra chars)
    assert verify_webhook_signature(payload, "invalid_non_hex_string_xyz", secret) is False
    assert verify_webhook_signature(payload, valid_sig[:-4], secret) is False
    assert verify_webhook_signature(payload, valid_sig + "00", secret) is False

    # 6. Vietnamese diacritics in payload and secret
    vn_payload = "Khách hàng Nguyễn Văn A đã duyệt hồ sơ tín dụng 500 triệu"
    vn_secret = "khóa_bí_mật_bảo_mật_cao_2026"
    vn_sig = hmac.new(vn_secret.encode("utf-8"), vn_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    assert verify_webhook_signature(vn_payload, vn_sig, vn_secret) is True
    assert verify_webhook_signature(vn_payload + " ", vn_sig, vn_secret) is False

    # 7. Null byte injection
    null_payload = b"payload\x00with\x00null\x00bytes"
    null_sig = hmac.new(secret.encode("utf-8"), null_payload, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(null_payload, null_sig, secret) is True
    assert verify_webhook_signature(null_payload + b"\x00", null_sig, secret) is False


def test_webhook_receiver_http_server_tamper_rejection():
    """
    Verify live WebhookReceiver HTTP server actively rejects tampered payloads with 401 Unauthorized
    and accepts legitimate signed payloads with 200 OK.
    """
    secret = "webhook-receiver-secret-test"
    receiver = WebhookReceiver(secret=secret)
    received_events = []
    receiver.on_event(lambda evt: received_events.append(evt))

    port = receiver.start_server(host="127.0.0.1", port=0)
    server_url = f"http://127.0.0.1:{port}"

    try:
        valid_payload = json.dumps({"decision_id": "dec-99", "status": "APPROVED"}).encode("utf-8")
        valid_sig = hmac.new(secret.encode("utf-8"), valid_payload, hashlib.sha256).hexdigest()

        # 1. Valid request -> 200 OK
        req = urllib.request.Request(
            server_url,
            data=valid_payload,
            headers={"Content-Type": "application/json", "X-Signature-SHA256": valid_sig},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body["status"] == "ok"

        assert len(received_events) == 1
        assert received_events[0]["decision_id"] == "dec-99"

        # 2. Tampered signature -> 401 Unauthorized
        bad_req = urllib.request.Request(
            server_url,
            data=valid_payload,
            headers={"Content-Type": "application/json", "X-Signature-SHA256": "bad_signature_hex"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req)
        assert exc_info.value.code == 401

        # Handlers should not have been called for bad request
        assert len(received_events) == 1
    finally:
        receiver.stop_server()
