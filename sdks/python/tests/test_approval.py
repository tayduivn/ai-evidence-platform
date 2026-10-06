"""Unit tests for approval subsystem: ApprovalHandle and ApprovalPoller."""

import pytest

from ai_evidence_sdk.approval.handle import ApprovalHandle
from ai_evidence_sdk.approval.states import ApprovalStatus
from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.exceptions import (
    ApprovalRejectedError,
    ApprovalTimeoutError,
    NetworkRetriesExhaustedError,
)


def test_approval_handle_mapping_contract():
    raw = {
        "status": "PENDING_APPROVAL",
        "decision_id": "dec-ml-12345",
        "poll_url": "/api/v1/decisions/dec-ml-12345/status",
        "correlation_id": "corr-test-1",
    }
    handle = ApprovalHandle(
        decision_id="dec-ml-12345",
        status="PENDING_APPROVAL",
        poll_url="/api/v1/decisions/dec-ml-12345/status",
        correlation_id="corr-test-1",
        raw_response=raw,
    )

    # Dictionary access assertions (satisfies test_tier1_sdk_python_request_approval_flow)
    assert handle["status"] == "PENDING_APPROVAL"
    assert "decision_id" in handle
    assert "poll_url" in handle
    assert handle["decision_id"] == "dec-ml-12345"
    assert handle.get("correlation_id") == "corr-test-1"
    assert len(handle) == 4
    assert set(iter(handle)) == {"status", "decision_id", "poll_url", "correlation_id"}

    # Object properties
    assert handle.decision_id == "dec-ml-12345"
    assert handle.status == "PENDING_APPROVAL"
    assert handle.poll_url == "/api/v1/decisions/dec-ml-12345/status"


def test_approval_polling_transition_to_approved(mock_gateway):
    mock_gateway.status_sequence = ["PENDING", "APPROVED"]
    mock_gateway.status_idx = 0

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "credit-xgboost", "score": 800})
        assert handle["status"] == "PENDING_APPROVAL"

        result = handle.wait(timeout=5.0, poll_interval=0.02)
        assert result.is_approved is True
        assert result.status == ApprovalStatus.APPROVED
        assert result.signature_hex is not None
        assert result.timed_out is False
    finally:
        client.close(timeout=1.0)


def test_approval_polling_4_eyes_transition(mock_gateway):
    # Transition: PENDING -> AWAITING_SECOND_APPROVAL -> APPROVED
    mock_gateway.status_sequence = [
        "PENDING",
        "AWAITING_SECOND_APPROVAL",
        "APPROVED",
    ]
    mock_gateway.status_idx = 0

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "credit-xgboost", "score": 850})
        result = client.wait_for_decision(handle, timeout=5.0, poll_interval=0.02)
        assert result.is_approved is True
        assert result.status == ApprovalStatus.APPROVED
    finally:
        client.close(timeout=1.0)


def test_approval_polling_rejection_graceful(mock_gateway):
    mock_gateway.status_sequence = ["PENDING", "REJECTED"]
    mock_gateway.status_idx = 0
    mock_gateway.rejection_reason = "Exceeds debt-to-income threshold"

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "credit-xgboost", "score": 500})
        result = handle.wait(timeout=5.0, poll_interval=0.02, raise_on_rejection=False)
        assert result.is_approved is False
        assert result.status == ApprovalStatus.REJECTED
        assert "Exceeds debt-to-income" in (result.rejection_reason or "")
    finally:
        client.close(timeout=1.0)


def test_approval_polling_rejection_raises(mock_gateway):
    mock_gateway.status_sequence = ["REJECTED"]
    mock_gateway.status_idx = 0
    mock_gateway.rejection_reason = "High fraud risk"

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "fraud-detector", "score": 99.0})
        with pytest.raises(ApprovalRejectedError) as exc_info:
            handle.wait(timeout=5.0, poll_interval=0.02, raise_on_rejection=True)
        assert "High fraud risk" in str(exc_info.value)
    finally:
        client.close(timeout=1.0)


def test_approval_polling_timeout_raises(mock_gateway):
    # Decision stays PENDING indefinitely
    mock_gateway.status_sequence = ["PENDING"]
    mock_gateway.status_idx = 0

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "credit-xgboost", "score": 700})
        with pytest.raises(ApprovalTimeoutError) as exc_info:
            handle.wait(timeout=0.1, poll_interval=0.02, raise_on_timeout=True)
        assert "timed out" in str(exc_info.value)
    finally:
        client.close(timeout=1.0)


def test_approval_polling_timeout_graceful(mock_gateway):
    mock_gateway.status_sequence = ["PENDING"]
    mock_gateway.status_idx = 0

    client = EvidenceClient(ingest_url=mock_gateway.ingest_url)
    try:
        handle = client.request_approval({"ai_system_id": "credit-xgboost", "score": 700})
        result = handle.wait(timeout=0.1, poll_interval=0.02, raise_on_timeout=False)
        assert result.timed_out is True
        assert result.is_approved is False
    finally:
        client.close(timeout=1.0)
