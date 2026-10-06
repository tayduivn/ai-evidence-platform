"""Unit tests for webhook signature verification and receiver."""

import hashlib
import hmac
import json
import urllib.request
import pytest

from ai_evidence_sdk.approval.webhook import WebhookReceiver, verify_webhook_signature


def test_verify_webhook_signature_valid():
    secret = "my-secret-key-123"
    payload = b'{"decision_id":"dec-123","status":"APPROVED"}'

    expected_sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    # Raw hex
    assert verify_webhook_signature(payload, expected_sig, secret) is True
    # With prefix
    assert verify_webhook_signature(payload, f"sha256={expected_sig}", secret) is True
    # With string payload
    assert verify_webhook_signature(payload.decode("utf-8"), expected_sig, secret) is True


def test_verify_webhook_signature_tampered():
    secret = "my-secret-key-123"
    payload = b'{"decision_id":"dec-123","status":"APPROVED"}'
    tampered = b'{"decision_id":"dec-123","status":"REJECTED"}'

    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(tampered, sig, secret) is False


def test_verify_webhook_signature_wrong_secret():
    secret = "my-secret-key-123"
    wrong_secret = "wrong-secret"
    payload = b'{"decision_id":"dec-123","status":"APPROVED"}'

    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(payload, sig, wrong_secret) is False


def test_webhook_receiver_server_dispatch():
    secret = "wh-secret-xyz"
    receiver = WebhookReceiver(secret=secret)

    received_events = []
    receiver.on_event(lambda evt: received_events.append(evt))

    port = receiver.start_server(host="127.0.0.1", port=0)
    server_url = f"http://127.0.0.1:{port}"

    try:
        payload = {"decision_id": "dec-wh-001", "status": "APPROVED"}
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

        # Send valid POST
        req = urllib.request.Request(
            server_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Signature-SHA256": sig,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200

        assert len(received_events) == 1
        assert received_events[0]["decision_id"] == "dec-wh-001"
        assert received_events[0]["status"] == "APPROVED"

        # Send invalid signature POST
        bad_req = urllib.request.Request(
            server_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Signature-SHA256": "bad-signature-hex",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req, timeout=3.0)
        assert exc_info.value.code == 401

    finally:
        receiver.stop_server()
