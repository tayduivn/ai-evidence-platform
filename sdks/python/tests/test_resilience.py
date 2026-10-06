"""Resilience, fault-tolerance, and zero-exception tests."""

import time
import pytest

from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.models import DropPolicy


def test_rapid_logging_under_dead_endpoint():
    """Verify that 100 rapid logging calls against offline endpoint succeed in < 5ms each."""
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=500,
    )

    try:
        durations_ms = []
        for i in range(100):
            t0 = time.perf_counter()
            success = client.log_decision(
                {"ai_system_id": "resilience-test", "score": 0.95, "iteration": i}
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            durations_ms.append(elapsed_ms)
            assert success is True

        assert max(durations_ms) < 5.0, f"Max latency was {max(durations_ms):.4f}ms"
        assert sum(durations_ms) / len(durations_ms) < 0.2
    finally:
        client.close(timeout=0.5)


def test_bounded_queue_saturation_drop_oldest():
    """Verify queue saturation under dead endpoint cleanly drops oldest without exceptions."""
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=10,
        drop_policy=DropPolicy.DROP_OLDEST,
    )

    try:
        # Enqueue 50 events into a size-10 buffer
        for i in range(50):
            res = client.log_decision({"i": i, "score": 100})
            assert res is True

        assert client.dropped_events == 40
        assert len(client.buffer_queue) == 10
    finally:
        client.close(timeout=0.5)


def test_bounded_queue_saturation_drop_newest():
    """Verify queue saturation under drop_newest policy rejects new items cleanly."""
    client = EvidenceClient(
        ingest_url="http://127.0.0.1:59999/down",
        max_queue_size=10,
        drop_policy=DropPolicy.DROP_NEWEST,
    )

    try:
        for i in range(10):
            assert client.log_decision({"i": i, "score": 100}) is True

        # Next 20 should return False
        for i in range(10, 30):
            assert client.log_decision({"i": i, "score": 100}) is False

        assert client.dropped_events == 20
        assert len(client.buffer_queue) == 10
    finally:
        client.close(timeout=0.5)


def test_fault_injection_server_500_caller_unaffected(mock_gateway):
    """Verify caller SLA is unaffected even when server returns 500 error."""
    mock_gateway.injected_status = 500
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)

    try:
        start_all = time.perf_counter()
        for i in range(20):
            t0 = time.perf_counter()
            success = client.log_decision({"i": i, "score": 800})
            duration_ms = (time.perf_counter() - t0) * 1000.0
            assert success is True
            assert duration_ms < 5.0

        total_ms = (time.perf_counter() - start_all) * 1000.0
        assert total_ms < 50.0  # Entire burst returns in < 50ms
    finally:
        client.close(timeout=0.5)
