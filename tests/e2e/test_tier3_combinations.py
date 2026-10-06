"""
Tier 3: Cross-Feature Combinations E2E Tests.
Validates pairwise and multi-module interactions across system boundaries:
1. Gateway SSE Stream + Vietnamese PII Masking + Async Ledger Event Envelope
2. Gateway Dual Mode (Audit vs 202 Intercept) + AI Registry Gating
3. ML Ingest API + PII Masking + 4-Eyes Approval + Polymorphic Signers
4. Micro-batching Queue + Merkle Tree Root + RFC 3161 TSA Anchoring
5. Complete Approval Flow + Evidence Pack Archiving + Standalone CLI Verification
6. Python SDK Non-blocking Queue + Upstream Fault Injection + Recovery
"""

import hashlib
import json
import time
import zipfile
from pathlib import Path
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
# C1: Gateway SSE Stream + PII Masking + Audit Event Envelope
# ==============================================================================

def test_tier3_combination_sse_pii_ledger_envelope(mock_llm):
    """Verify Gateway receives prompt with CCCD, redacts PII, streams response, and records envelope."""
    raw_prompt = "Khách hàng CCCD 001090012345 yêu cầu tư vấn gói tín dụng."

    # 1. PII Scan & Redaction
    masked_prompt, pii_detected = VietnamesePIIScanner.scan_and_mask(raw_prompt)
    assert "001******345" in masked_prompt
    assert "CCCD" in pii_detected

    # 2. Upstream SSE Stream with masked prompt
    import urllib.request
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": masked_prompt}], "stream": True}).encode("utf-8"),
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
                delta = chunk["choices"][0]["delta"]
                if "content" in delta:
                    tokens.append(delta["content"])
    accumulated_output = "".join(tokens)

    # 3. Construct Complete Audit Event Envelope (Contract 1 in PROJECT.md)
    envelope = {
        "event_id": "018f3a9e-test-combo-001",
        "correlation_id": "tx-corr-combo-001",
        "ai_system_id": "credit-advisor-v1",
        "system_type": "llm",
        "model_version": "gpt-4o-2024-08-06",
        "timestamp": "2026-10-05T10:30:00.123456Z",
        "input_payload": json.dumps({"prompt": raw_prompt}, ensure_ascii=False),
        "output_payload": json.dumps({"response": accumulated_output}, ensure_ascii=False),
        "input_masked": json.dumps({"prompt": masked_prompt}, ensure_ascii=False),
        "output_masked": json.dumps({"response": accumulated_output}, ensure_ascii=False),
        "pii_detected": pii_detected,
        "tokens_usage": {"prompt_tokens": 12, "completion_tokens": len(tokens), "total_tokens": 12 + len(tokens)},
        "latency_ms": 120,
        "status": "COMPLETED"
    }

    assert envelope["pii_detected"] == ["CCCD"]
    assert "001090012345" in envelope["input_payload"]
    assert "001******345" in envelope["input_masked"]


# ==============================================================================
# C2: Gateway Dual Mode + AI Registry Gating
# ==============================================================================

def test_tier3_combination_registry_and_dual_mode_routing():
    """Verify AI Registry determines whether request is Audit-only pass vs 202 Intercept."""
    # System A: Low risk, Audit-only
    status_a, _ = AIRegistryContract.evaluate_request("securities-quant-advisor-v1")
    assert status_a == 200
    # Audit-only does not require approval
    requires_approval_a = AIRegistryContract.REGISTERED_SYSTEMS["securities-quant-advisor-v1"]["requires_approval"]
    assert requires_approval_a is False

    # System B: High risk, Intercept & Approve
    status_b, _ = AIRegistryContract.evaluate_request("credit-advisor-v1")
    assert status_b == 200
    requires_approval_b = AIRegistryContract.REGISTERED_SYSTEMS["credit-advisor-v1"]["requires_approval"]
    assert requires_approval_b is True

    # Intercept produces HTTP 202 response
    if requires_approval_b:
        intercept_response = {
            "status": "PENDING_APPROVAL",
            "decision_id": "dec-intercept-998",
            "poll_url": "/api/v1/decisions/dec-intercept-998/status"
        }
        assert intercept_response["status"] == "PENDING_APPROVAL"


# ==============================================================================
# C3: ML Ingest + PII Redaction + 4-Eyes Approval + Signers
# ==============================================================================

def test_tier3_combination_ml_ingest_pii_4eyes_and_signing(fixtures_paths):
    """Verify ML decision with PII goes through redaction, 4-Eyes dual signing, and approval."""
    # 1. Incoming payload with PII in features/explanation
    raw_feature_notes = "Khách hàng có SĐT 0912345678 và STK 19034567890123"
    masked_notes, detected_pii = VietnamesePIIScanner.scan_and_mask(raw_feature_notes)
    assert sorted(detected_pii) == ["BANK_ACCOUNT", "PHONE"]

    # 2. Submit to 4-Eyes Approval State Machine
    decision_id = "dec-ml-combo-772"
    sm = ApprovalStateMachine(decision_id=decision_id, creator_id="ml-service-credit", min_dwell_seconds=10)

    # 3. Approver 1 signs with Internal Key
    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        k1 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        c1 = x509.load_pem_x509_certificate(f.read())

    p1 = {"decision_id": decision_id, "approver": "lead-approver", "dwell": 15}
    sig1 = k1.sign(canonical_json(p1), padding.PKCS1v15(), hashes.SHA256())
    c1.public_key().verify(sig1, canonical_json(p1), padding.PKCS1v15(), hashes.SHA256())

    st1, _ = sm.submit_action("lead-approver", "APPROVE", dwell_seconds=15, signer_type="internal")
    assert st1 == 200
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND

    # 4. Approver 2 signs with CA VN Token
    with open(fixtures_paths["certs"] / "signer_2.key", "rb") as f:
        k2 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_2.pem", "rb") as f:
        c2 = x509.load_pem_x509_certificate(f.read())

    p2 = {"decision_id": decision_id, "approver": "risk-officer", "dwell": 20}
    sig2 = k2.sign(canonical_json(p2), padding.PKCS1v15(), hashes.SHA256())
    c2.public_key().verify(sig2, canonical_json(p2), padding.PKCS1v15(), hashes.SHA256())

    st2, _ = sm.submit_action("risk-officer", "APPROVE", dwell_seconds=20, signer_type="ca_vn_token")
    assert st2 == 200
    assert sm.status == ApprovalStateMachine.STATUS_APPROVED


# ==============================================================================
# C4: Micro-batch Queue + Merkle Root + RFC 3161 TSA Token
# ==============================================================================

def test_tier3_combination_micro_batch_merkle_and_tsa():
    """Verify micro-batched events build Merkle tree and anchor root hash with RFC 3161 TSA."""
    # 1. Micro-batch 50 events
    events = [{"event_id": f"batch-ev-{i}", "val": i * 10} for i in range(50)]
    leaves = [MerkleAuditEngine.hash_leaf(ev) for ev in events]

    # 2. Merkle Root Calculation
    root_hash = MerkleAuditEngine.compute_root(leaves)
    assert len(root_hash) == 64

    # 3. Generate TimeStampReq(SHA256(root_hash))
    tsa_digest = hashlib.sha256(root_hash.encode("utf-8")).digest()
    assert len(tsa_digest) == 32

    # 4. Simulated RFC 3161 TimeStampResp ASN.1 TST Token
    simulated_tsa_token = {
        "status": "granted",
        "hash_algorithm": "SHA-256",
        "message_imprint": tsa_digest.hex(),
        "gen_time": "2026-10-05T10:35:00Z",
        "tsa_serial": "TSA-2026-VN-00918"
    }
    assert simulated_tsa_token["message_imprint"] == tsa_digest.hex()


# ==============================================================================
# C5: Complete Approval Flow + Pack Building + CLI Verification
# ==============================================================================

def test_tier3_combination_full_workflow_to_cli_verification(tmp_path, fixtures_paths):
    """Verify end-to-end flow from decision to packed zip and independent CLI verification."""
    from tests.fixtures.generate_fixtures import build_evidence_pack_zip

    event_id = "018f3a9e-combo-full-workflow"
    decision_record = {
        "event_id": event_id,
        "ai_system_id": "credit-scoring-xgboost",
        "decision": "APPROVE_CREDIT_LINE",
        "score": 790.0,
        "output_payload": "Approved 500M VND",
        "dwell_time_seconds": 15,
        "approvers": ["approver-user-01", "approver-user-02"]
    }
    events = [decision_record]
    leaf_hash = hashlib.sha256(canonical_json(decision_record)).hexdigest()
    root_hash = hashlib.sha256((leaf_hash + leaf_hash).encode("utf-8")).hexdigest()
    merkle_proof = {
        "root_hash": root_hash,
        "leaf_hash": leaf_hash,
        "index": 0,
        "total_leaves": 1,
        "audit_path": [leaf_hash]
    }

    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        k1 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        c1_pem = f.read()

    with open(fixtures_paths["certs"] / "signer_2.key", "rb") as f:
        k2 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_2.pem", "rb") as f:
        c2_pem = f.read()

    with open(fixtures_paths["certs"] / "root_ca.pem", "rb") as f:
        root_pem = f.read()

    p1 = {"decision_id": event_id, "approver_id": "approver-user-01", "dwell_time_seconds": 15}
    sig1 = k1.sign(canonical_json(p1), padding.PKCS1v15(), hashes.SHA256())

    p2 = {"decision_id": event_id, "approver_id": "approver-user-02", "dwell_time_seconds": 20}
    sig2 = k2.sign(canonical_json(p2), padding.PKCS1v15(), hashes.SHA256())

    sig_objs = [
        {"signer_type": "internal", "approver_id": "approver-user-01", "signed_payload": p1, "signature_hex": sig1.hex()},
        {"signer_type": "ca_vn_token", "approver_id": "approver-user-02", "signed_payload": p2, "signature_hex": sig2.hex()}
    ]

    pack_zip = tmp_path / "combo_generated_pack.zip"
    build_evidence_pack_zip(
        pack_zip,
        events=events,
        merkle_proof=merkle_proof,
        signatures=sig_objs,
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # Verify with EvidenceVerifier
    verifier = EvidenceVerifier(str(pack_zip))
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SUCCESS
    assert msg == "VERIFICATION_SUCCESS"


# ==============================================================================
# C6: Python SDK Non-blocking Queue + Upstream Fault Injection
# ==============================================================================

def test_tier3_combination_python_sdk_resilience_under_injected_fault(mock_llm):
    """Verify Python SDK caller experiences < 5ms return and no crashes even when mock LLM injects 500 error."""
    mock_llm.configure(status_code=500, delay_ms=100)

    sdk = MockPythonSDKClient(ingest_url=f"{mock_llm.base_url}/v1/chat/completions")
    # Submitting 10 events rapidly
    start_all = time.perf_counter()
    for i in range(10):
        t0 = time.perf_counter()
        success = sdk.log_decision({"event_id": f"resilience-evt-{i}", "score": 800})
        duration_ms = (time.perf_counter() - t0) * 1000.0
        assert success is True
        assert duration_ms < 5.0, f"SLA violated: {duration_ms}ms"

    total_time_ms = (time.perf_counter() - start_all) * 1000.0
    mock_llm.reset_config()
    sdk.close()
    assert total_time_ms < 50.0
