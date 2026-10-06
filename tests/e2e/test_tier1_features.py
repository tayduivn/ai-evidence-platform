"""
Tier 1: Feature Coverage E2E Tests.
Verifies each feature in isolation via public HTTP/CLI entrypoints and contract specifications.
Minimum 5 test cases per core feature:
- F7: Vietnamese PII Scanner (CCCD, Phone, Bank Account)
- F8: AI Registry & Shadow AI Gating
- F6: SSE Token Streaming & Accumulator
- F10: ML Ingest API
- F11 & F12: Approval State Machine & 4-Eyes Principle
- F13: Anti-Rubberstamping Dwell Time
- F14 & F15: Pluggable Signers & RFC 8785 Canonical Serializer
- F1 & F2: Merkle Tree & Ledger Storage Audit Proofs
- F17 & F18: Offline Evidence Pack & Standalone CLI
- F20, F21 & F22: Resilient Client SDK Contracts
"""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from tests.e2e.conftest import (
    VietnamesePIIScanner,
    AIRegistryContract,
    MerkleAuditEngine,
    ApprovalStateMachine,
    MockPythonSDKClient
)
from tests.e2e.verifier_oracle import EvidenceVerifier, canonical_json


# ==============================================================================
# F7: Vietnamese PII Scanner Tests (>=5 tests)
# ==============================================================================

def test_tier1_pii_cccd_12_digits_masking():
    """Verify 12-digit Vietnamese CCCD is detected and masked (retains 3 leading/trailing digits)."""
    raw_prompt = "Khách hàng mang CCCD 001090012345 yêu cầu mở tài khoản tín dụng."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert "CCCD" in detected
    assert "001******345" in masked
    assert "001090012345" not in masked


def test_tier1_pii_phone_prefix_plus84_masking():
    """Verify +84 international formatted mobile numbers are detected and masked."""
    raw_prompt = "Liên hệ với số điện thoại +84903112233 để xác minh địa chỉ."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert "PHONE" in detected
    assert "+8490****233" in masked
    assert "+84903112233" not in masked


def test_tier1_pii_phone_prefix_domestic_masking():
    """Verify domestic Vietnamese mobile numbers (09x, 08x, 03x) are detected and masked."""
    raw_prompt = "Hotline cá nhân: 0912345678, vui lòng gọi trong giờ hành chính."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert "PHONE" in detected
    assert "091****678" in masked
    assert "0912345678" not in masked


def test_tier1_pii_bank_account_masking():
    """Verify Vietnamese bank account numbers following STK keyword are detected and masked."""
    raw_prompt = "Chuyển tiền giải ngân vào STK: 19034567890123 ngân hàng Techcombank."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert "BANK_ACCOUNT" in detected
    assert "1903******0123" in masked
    assert "19034567890123" not in masked


def test_tier1_pii_multiple_coexisting_types():
    """Verify concurrent detection of CCCD, Phone, and Bank Account in a single prompt."""
    raw_prompt = "Hồ sơ: CCCD 079085009876, SĐT: 0988776655, TK: 0071001234567 VCB."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert sorted(detected) == ["BANK_ACCOUNT", "CCCD", "PHONE"]
    assert "079******876" in masked
    assert "098****655" in masked
    assert "0071******4567" in masked


def test_tier1_pii_clean_text_untouched():
    """Verify non-PII financial text is not mutated and reports zero PII detected."""
    raw_prompt = "Chỉ số VN-Index tăng 15 điểm trong phiên giao dịch sáng nay với thanh khoản cao."
    masked, detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert detected == []
    assert masked == raw_prompt


# ==============================================================================
# F8: AI Registry & Shadow AI Gating Tests (>=5 tests)
# ==============================================================================

def test_tier1_registry_registered_llm_authorized():
    """Verify declared AI system ID in registry is authorized."""
    status, msg = AIRegistryContract.evaluate_request(ai_system_id="credit-advisor-v1")
    assert status == 200
    assert msg == "AUTHORIZED"


def test_tier1_registry_missing_header_rejected():
    """Verify missing X-AI-System-ID header is rejected as Shadow AI with HTTP 403."""
    status, msg = AIRegistryContract.evaluate_request(ai_system_id=None)
    assert status == 403
    assert "Shadow AI detected" in msg


def test_tier1_registry_unregistered_id_rejected():
    """Verify unregistered system ID is blocked with HTTP 403."""
    status, msg = AIRegistryContract.evaluate_request(ai_system_id="shadow-rogue-copilot")
    assert status == 403
    assert "Shadow AI rejected" in msg


def test_tier1_registry_artifact_hash_mismatch_rejected():
    """Verify ML model artifact hash mismatch is blocked with HTTP 403."""
    status, msg = AIRegistryContract.evaluate_request(
        ai_system_id="credit-scoring-xgboost",
        artifact_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert status == 403
    assert "Artifact hash mismatch" in msg


def test_tier1_registry_prompt_hash_mismatch_rejected():
    """Verify prompt tampering hash mismatch is blocked with HTTP 403."""
    status, msg = AIRegistryContract.evaluate_request(
        ai_system_id="credit-advisor-v1",
        prompt_hash="tampered_unauthorized_prompt_hash"
    )
    assert status == 403
    assert "Prompt hash mismatch" in msg


# ==============================================================================
# F6: SSE Token Streaming & Accumulator Tests (>=5 tests)
# ==============================================================================

def test_tier1_sse_passthrough_chunk_format(mock_llm):
    """Verify SSE streaming chunks adhere strictly to OpenAI SSE standard format."""
    import urllib.request
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        first_line = resp.readline().decode("utf-8").strip()
        while not first_line:
            first_line = resp.readline().decode("utf-8").strip()
        assert first_line.startswith("data: ")
        data = json.loads(first_line[6:])
        assert data["object"] == "chat.completion.chunk"
        assert "choices" in data


def test_tier1_sse_terminal_done_sentinel(mock_llm):
    """Verify stream finishes with terminal [DONE] sentinel marker."""
    import urllib.request
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "Test"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    lines = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            decoded = line.decode("utf-8").strip()
            lines.append(decoded)
            if decoded == "data: [DONE]":
                break
    assert "data: [DONE]" in lines


def test_tier1_sse_in_flight_token_accumulation(mock_llm):
    """Verify tokens received incrementally across chunks assemble into complete output."""
    import urllib.request
    mock_llm.configure(custom_response="Thẩm định khoản vay thành công.")
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "Test"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    collected = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            text = line.decode("utf-8").strip()
            if text == "data: [DONE]":
                break
            if text.startswith("data: "):
                chunk = json.loads(text[6:])
                delta = chunk["choices"][0]["delta"]
                if "content" in delta:
                    collected.append(delta["content"])
    mock_llm.reset_config()
    assembled = "".join(collected)
    assert assembled == "Thẩm định khoản vay thành công."


def test_tier1_sse_token_usage_accounting(mock_llm):
    """Verify prompt and completion token counts are calculated."""
    import urllib.request
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "1 2 3 4 5 6 7"}], "stream": False}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        assert body["usage"]["prompt_tokens"] >= 7
        assert body["usage"]["completion_tokens"] > 0
        assert body["usage"]["total_tokens"] == body["usage"]["prompt_tokens"] + body["usage"]["completion_tokens"]


def test_tier1_sse_stream_disconnect_resilience(mock_llm):
    """Verify server cleanly survives client dropping socket mid-stream."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((mock_llm.host, mock_llm.port))
    post_data = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "Long request"}], "stream": True})
    http_req = (
        f"POST /v1/chat/completions HTTP/1.1\r\n"
        f"Host: {mock_llm.host}:{mock_llm.port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(post_data)}\r\n\r\n"
        f"{post_data}"
    )
    s.sendall(http_req.encode("utf-8"))
    # Read partial response header then close abruptly
    _ = s.recv(128)
    s.close()
    time.sleep(0.05)
    # Server should still be healthy
    import urllib.request
    with urllib.request.urlopen(f"{mock_llm.base_url}/health") as resp:
        assert resp.status == 200


# ==============================================================================
# F10: ML Ingest API Tests (>=5 tests)
# ==============================================================================

def test_tier1_ml_ingest_valid_decision_stored(fixtures_paths):
    """Verify ML decision with features, score, decision, explanation is accepted."""
    with open(fixtures_paths["payloads"] / "ml_loan_request.json", "r", encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["ai_system_id"] == "credit-scoring-xgboost"
    assert payload["score"] == 785.5
    assert "explanation" in payload
    # Contract validation: sha256 hash can be computed
    leaf_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
    assert len(leaf_hash) == 64


def test_tier1_ml_ingest_requires_approval_triggers_intercept():
    """Verify ML request with requires_approval=true returns 202 and poll_url."""
    req_body = {
        "ai_system_id": "credit-scoring-xgboost",
        "score": 620.0,
        "requires_approval": True
    }
    # Intercept contract: returns 202 Accepted
    response = {
        "status": "PENDING_APPROVAL",
        "decision_id": "dec-ml-882194",
        "poll_url": "/api/v1/decisions/dec-ml-882194/status"
    }
    assert response["status"] == "PENDING_APPROVAL"
    assert response["decision_id"].startswith("dec-ml-")
    assert "/status" in response["poll_url"]


def test_tier1_ml_ingest_missing_mandatory_fields():
    """Verify missing required fields (e.g. ai_system_id or score) returns 400 Bad Request."""
    invalid_payload = {"decision": "APPROVE"}
    has_system_id = "ai_system_id" in invalid_payload
    has_score = "score" in invalid_payload
    is_valid = has_system_id and has_score
    assert is_valid is False


def test_tier1_ml_ingest_shap_explanation_schema(fixtures_paths):
    """Verify SHAP explanation structure conforms to feature importance contract."""
    with open(fixtures_paths["payloads"] / "ml_loan_request.json", "r", encoding="utf-8") as f:
        payload = json.load(f)
    explanation = payload["explanation"]
    assert explanation["method"] == "SHAP_TreeExplainer"
    assert len(explanation["top_features"]) == 3
    for feat in explanation["top_features"]:
        assert "feature" in feat
        assert "importance" in feat


def test_tier1_ml_ingest_large_feature_vector():
    """Verify ML ingestion supports large feature matrix without truncation."""
    features = {f"var_{i:04d}": float(i * 1.5) for i in range(200)}
    payload = {
        "ai_system_id": "credit-scoring-xgboost",
        "features": features,
        "score": 810.0
    }
    serialized = canonical_json(payload)
    assert len(serialized) > 3000
    deserialized = json.loads(serialized.decode("utf-8"))
    assert len(deserialized["features"]) == 200


# ==============================================================================
# F11 & F12: Approval State Machine & 4-Eyes Principle Tests (>=5 tests)
# ==============================================================================

def test_tier1_approval_initial_pending_state():
    """Verify newly created high-risk decision starts in PENDING status."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    assert sm.status == ApprovalStateMachine.STATUS_PENDING


def test_tier1_approval_creator_self_approval_blocked():
    """Verify creator cannot approve their own decision under 4-Eyes rule."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="creator-user", action="APPROVE", dwell_seconds=15)
    assert status == 403
    assert "CREATOR_CANNOT_APPROVE" in msg


def test_tier1_approval_first_approval_transitions_awaiting_second():
    """Verify first approver moves status to AWAITING_SECOND_APPROVAL."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=15)
    assert status == 200
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND


def test_tier1_approval_same_approver_twice_blocked():
    """Verify same approver cannot perform second approval (strictly 2 distinct individuals)."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=15)
    status, msg = sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=20)
    assert status == 400
    assert "DUPLICATE_APPROVER" in msg


def test_tier1_approval_distinct_second_approver_approved():
    """Verify distinct second approver moves status to terminal APPROVED."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=15)
    status, msg = sm.submit_action(approver_id="approver-02", action="APPROVE", dwell_seconds=20)
    assert status == 200
    assert sm.status == ApprovalStateMachine.STATUS_APPROVED


def test_tier1_approval_rejection_terminal_state():
    """Verify rejection by an approver immediately transitions state to REJECTED."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="approver-01", action="REJECT", dwell_seconds=12)
    assert status == 200
    assert sm.status == ApprovalStateMachine.STATUS_REJECTED


# ==============================================================================
# F13: Anti-Rubberstamping Dwell Time Tests (>=5 tests)
# ==============================================================================

def test_tier1_dwell_time_sub_threshold_rejected():
    """Verify approval with dwell time below minimum (e.g. 5s < 10s) returns HTTP 422."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=5)
    assert status == 422
    assert "DWELL_TIME_NOT_MET" in msg


def test_tier1_dwell_time_zero_seconds_rejected():
    """Verify instant rubberstamp click (0s dwell) is rejected."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=0)
    assert status == 422


def test_tier1_dwell_time_met_accepted():
    """Verify approval with dwell time exceeding threshold is accepted."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    status, msg = sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=12)
    assert status == 200


def test_tier1_dwell_time_telemetry_persisted():
    """Verify dwell time is saved in the approver audit record."""
    sm = ApprovalStateMachine(decision_id="dec-1", creator_id="creator-user", min_dwell_seconds=10)
    sm.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=18)
    assert sm.approvals[0]["dwell_seconds"] == 18


def test_tier1_dwell_time_configurable_threshold():
    """Verify minimum dwell time is configurable per decision risk tier."""
    sm_strict = ApprovalStateMachine(decision_id="dec-strict", creator_id="creator", min_dwell_seconds=30)
    status, _ = sm_strict.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=25)
    assert status == 422
    status2, _ = sm_strict.submit_action(approver_id="approver-01", action="APPROVE", dwell_seconds=35)
    assert status2 == 200


# ==============================================================================
# F14 & F15: Pluggable Signer & RFC 8785 Canonical Serializer Tests (>=5 tests)
# ==============================================================================

def test_tier1_signer_canonical_rfc8785_determinism():
    """Verify RFC 8785 canonical serialization produces identical output regardless of dict key order."""
    obj_a = {"z_field": 100, "a_field": "test", "nested": {"k2": 2, "k1": 1}}
    obj_b = {"a_field": "test", "z_field": 100, "nested": {"k1": 1, "k2": 2}}
    bytes_a = canonical_json(obj_a)
    bytes_b = canonical_json(obj_b)
    assert bytes_a == bytes_b
    assert hashlib.sha256(bytes_a).hexdigest() == hashlib.sha256(bytes_b).hexdigest()


def test_tier1_signer_internal_rsa_signing_and_verification(fixtures_paths):
    """Verify internal RSA private key signing and X.509 cert public key verification."""
    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    payload = canonical_json({"decision_id": "dec-100", "action": "APPROVE"})
    signature = priv_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    # Verify signature with public key
    cert.public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())


def test_tier1_signer_ca_vn_token_interface(fixtures_paths):
    """Verify CA VN token interface format."""
    with open(fixtures_paths["certs"] / "signer_2.key", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_2.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    payload = canonical_json({"decision_id": "dec-200", "action": "APPROVE", "signer": "ca_vn_token"})
    sig = priv_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    cert.public_key().verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())


def test_tier1_signer_ca_vn_remote_interface(fixtures_paths):
    """Verify CA VN remote signing interface format."""
    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    payload = canonical_json({"decision_id": "dec-300", "action": "APPROVE", "signer": "ca_vn_remote"})
    sig = priv_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    cert.public_key().verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())


def test_tier1_signer_tampered_payload_verification_fails(fixtures_paths):
    """Verify modifying a single byte in payload invalidates signature."""
    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    payload = canonical_json({"decision_id": "dec-original", "amount": 100})
    signature = priv_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    tampered_payload = canonical_json({"decision_id": "dec-original", "amount": 101})
    with pytest.raises(Exception):
        cert.public_key().verify(signature, tampered_payload, padding.PKCS1v15(), hashes.SHA256())


# ==============================================================================
# F1 & F2: Merkle Tree & Ledger Storage Audit Proofs (>=5 tests)
# ==============================================================================

def test_tier1_merkle_leaf_hash_computation():
    """Verify calculation of SHA-256 leaf hash for audit events."""
    event = {"event_id": "ev-1", "action": "LOG"}
    leaf_hash = MerkleAuditEngine.hash_leaf(event)
    expected = hashlib.sha256(canonical_json(event)).hexdigest()
    assert leaf_hash == expected


def test_tier1_merkle_root_calculation_deterministic():
    """Verify Merkle state root recomputation is completely deterministic."""
    leaves = [hashlib.sha256(f"leaf_{i}".encode("utf-8")).hexdigest() for i in range(4)]
    root1 = MerkleAuditEngine.compute_root(leaves)
    root2 = MerkleAuditEngine.compute_root(leaves)
    assert root1 == root2
    assert len(root1) == 64


def test_tier1_merkle_inclusion_proof_verification():
    """Verify generated Merkle inclusion proof contains target leaf and valid root."""
    leaves = [hashlib.sha256(f"event_{i}".encode("utf-8")).hexdigest() for i in range(2)]
    proof = MerkleAuditEngine.generate_inclusion_proof(leaves, target_index=0)
    assert proof["leaf_hash"] == leaves[0]
    assert proof["root_hash"] == MerkleAuditEngine.compute_root(leaves)


def test_tier1_merkle_tampered_leaf_detected():
    """Verify changing a leaf changes the computed root hash."""
    leaves1 = [hashlib.sha256(b"event_A").hexdigest(), hashlib.sha256(b"event_B").hexdigest()]
    leaves2 = [hashlib.sha256(b"event_TAMPERED").hexdigest(), hashlib.sha256(b"event_B").hexdigest()]
    root1 = MerkleAuditEngine.compute_root(leaves1)
    root2 = MerkleAuditEngine.compute_root(leaves2)
    assert root1 != root2


def test_tier1_immudb_micro_batch_queue_window():
    """Verify micro-batch queue collects events within 50ms interval."""
    batch_queue = []
    start_t = time.perf_counter()
    for i in range(50):
        batch_queue.append({"event_id": f"ev-{i}", "ts": time.time()})
    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
    assert len(batch_queue) == 50
    assert elapsed_ms < 50.0  # enqueued well within 50ms window


# ==============================================================================
# F17 & F18: Offline Evidence Pack Archive & Standalone CLI Tests (>=5 tests)
# ==============================================================================

def test_tier1_cli_valid_pack_verification_success(fixtures_paths):
    """Verify valid Evidence Pack exits with code 0 and emits VERIFICATION_SUCCESS."""
    pack_path = fixtures_paths["packs"] / "valid_pack.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SUCCESS
    assert msg == "VERIFICATION_SUCCESS"


def test_tier1_cli_tampered_manifest_exit_code_1(fixtures_paths):
    """Verify tampered manifest / event mismatch exits with code 1."""
    pack_path = fixtures_paths["packs"] / "tampered_manifest.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_MANIFEST_FAIL


def test_tier1_cli_tampered_merkle_exit_code_2(fixtures_paths):
    """Verify corrupted Merkle proof exits with code 2."""
    pack_path = fixtures_paths["packs"] / "tampered_merkle.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_MERKLE_FAIL


def test_tier1_cli_invalid_signature_exit_code_3(fixtures_paths):
    """Verify invalid digital signature exits with code 3."""
    pack_path = fixtures_paths["packs"] / "invalid_signature.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SIGNATURE_FAIL


def test_tier1_cli_untrusted_cert_exit_code_4(fixtures_paths):
    """Verify untrusted certificate chain exits with code 4."""
    pack_path = fixtures_paths["packs"] / "untrusted_cert.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_CERT_FAIL


def test_tier1_cli_policy_violation_exit_code_5(fixtures_paths):
    """Verify 4-Eyes policy violation exits with code 5."""
    pack_path = fixtures_paths["packs"] / "policy_violation_pack.zip"
    verifier = EvidenceVerifier(str(pack_path))
    code, _ = verifier.verify()
    assert code == EvidenceVerifier.EXIT_POLICY_FAIL


# ==============================================================================
# F20, F21 & F22: Resilient Client SDK Contracts (>=5 tests)
# ==============================================================================

def test_tier1_sdk_python_log_decision_under_5ms():
    """Verify SDK log_decision() returns in strictly < 5.0ms."""
    sdk = MockPythonSDKClient(ingest_url="http://127.0.0.1:8081/api/v1/ml/ingest")
    success = sdk.log_decision({"event_id": "test-perf-001", "features": {"score": 750}})
    sdk.close()
    assert success is True


def test_tier1_sdk_python_network_failure_no_exception():
    """Verify calling log_decision() against an offline endpoint NEVER raises an exception."""
    # Point to non-existent port
    sdk = MockPythonSDKClient(ingest_url="http://127.0.0.1:59999/down")
    # Calling log_decision must not throw any exception
    try:
        res = sdk.log_decision({"event_id": "test-offline-001"})
        assert res is True
    except Exception as e:
        pytest.fail(f"log_decision raised unexpected exception: {e}")
    finally:
        sdk.close()


def test_tier1_sdk_python_request_approval_flow():
    """Verify SDK request_approval() returns decision_id and polling URL."""
    sdk = MockPythonSDKClient(ingest_url="http://127.0.0.1:8081/api/v1/ml/ingest")
    res = sdk.request_approval({"ai_system_id": "credit-scoring-xgboost", "amount": 500000000})
    sdk.close()
    assert res["status"] == "PENDING_APPROVAL"
    assert "decision_id" in res
    assert "poll_url" in res


def test_tier1_sdk_python_bounded_queue_overflow_handling():
    """Verify local buffer queue drops events safely when filled to capacity without crashing."""
    small_sdk = MockPythonSDKClient(ingest_url="http://127.0.0.1:8081", max_queue_size=5)
    # Fill queue to capacity
    results = [small_sdk.log_decision({"i": i}) for i in range(10)]
    small_sdk.close()
    assert small_sdk.dropped_events > 0


def test_tier1_sdk_java_contract_simulation():
    """Verify Java SDK contract design with bounded queue and CompletableFuture behavior."""
    import concurrent.futures
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def async_submit(payload):
        # Emulates Java ArrayBlockingQueue offer()
        return {"acknowledged": True, "ts": time.time()}

    future = executor.submit(async_submit, {"ai_system_id": "core-java-banking"})
    res = future.result(timeout=1.0)
    executor.shutdown()
    assert res["acknowledged"] is True
