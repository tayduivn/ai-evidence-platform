"""Unit tests for EvidenceClient facade, contracts, and resilience."""

import time
import pytest

from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.exceptions import PIIValidationError
from ai_evidence_sdk.models import MLDecisionEvent


def test_client_log_decision_success(mock_gateway):
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        success = client.log_decision(
            {"ai_system_id": "credit-model", "score": 750.0, "features": {"income": 50000000}}
        )
        assert success is True
        client.flush(timeout=1.0)
        assert len(mock_gateway.received_posts) >= 1
    finally:
        client.close(timeout=1.0)


def test_client_log_decision_under_5ms_contract(mock_gateway):
    """SLA Contract: log_decision() must complete in strictly < 5.0ms."""
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        t0 = time.perf_counter()
        success = client.log_decision({"event_id": "test-perf-001", "score": 750})
        duration_ms = (time.perf_counter() - t0) * 1000.0

        assert success is True
        assert duration_ms < 5.0, f"Call exceeded 5.0ms SLA: {duration_ms:.4f}ms"
    finally:
        client.close(timeout=1.0)


def test_client_network_offline_never_raises_exception():
    """Resilience Contract: logging against offline endpoint NEVER raises exception."""
    dead_client = EvidenceClient(ingest_url="http://127.0.0.1:59999/down")
    try:
        success = dead_client.log_decision({"event_id": "test-offline-001", "score": 500})
        assert success is True
    finally:
        dead_client.close(timeout=0.5)


def test_client_bounded_queue_overflow_handling():
    """Buffer Contract: bounded queue drops events safely when filled to capacity."""
    small_client = EvidenceClient(ingest_url="http://127.0.0.1:8081", max_queue_size=5)
    try:
        results = [small_client.log_decision({"i": i, "score": 100}) for i in range(10)]
        assert small_client.dropped_events > 0
    finally:
        small_client.close(timeout=0.5)


def test_client_request_approval_contract(mock_gateway):
    """Approval Contract: returns ApprovalHandle with status, decision_id, and poll_url."""
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval(
            {"ai_system_id": "credit-scoring-xgboost", "amount": 500000000, "score": 750.0}
        )
        assert handle["status"] == "PENDING_APPROVAL"
        assert "decision_id" in handle
        assert "poll_url" in handle
    finally:
        client.close(timeout=1.0)


def test_client_pii_pre_validation_block_mode(mock_gateway):
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        event_with_pii = {
            "ai_system_id": "loan-advisor",
            "score": 650.0,
            "features": {"note": "Khách hàng CCCD 001090012345 cần vay"},
        }

        # With block mode, PIIValidationError must be raised before network transmission
        with pytest.raises(PIIValidationError) as exc_info:
            client.request_approval(
                event_with_pii,
                pre_validate_pii=True,
                pii_mode="block",
            )
        assert "CCCD" in exc_info.value.detected_types
        # Confirm no request was dispatched to gateway
        assert len(mock_gateway.received_posts) == 0
    finally:
        client.close(timeout=1.0)


def test_client_pii_pre_validation_mask_mode(mock_gateway):
    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        event_with_pii = {
            "ai_system_id": "loan-advisor",
            "score": 650.0,
            "features": {"note": "Khách hàng CCCD 001090012345 cần vay"},
        }

        handle = client.request_approval(
            event_with_pii,
            pre_validate_pii=True,
            pii_mode="mask",
        )
        assert handle["status"] == "PENDING_APPROVAL"
        # Confirm masked payload was sent to gateway
        last_post = mock_gateway.received_posts[-1]["payload"]
        assert "001******345" in last_post["features"]["note"]
        assert "001090012345" not in last_post["features"]["note"]
    finally:
        client.close(timeout=1.0)


def test_client_context_manager(mock_gateway):
    with EvidenceClient(ingest_url=mock_gateway.ingest_url) as client:
        client.log_decision({"ai_system_id": "ctx-model", "score": 900})
        client.flush(timeout=1.0)
    assert client.is_running is False
