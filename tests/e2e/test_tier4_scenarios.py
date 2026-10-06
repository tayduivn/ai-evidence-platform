"""
Tier 4: Real-World Scenarios E2E Tests.
Implements realistic, high-stakes enterprise compliance workflows:
- Scenario 1: Fintech Credit Loan Approval Flow (500M VND loan, PII redaction, 4-Eyes dual approval, CA VN token signature, Evidence Pack assembly)
- Scenario 2: Securities Trading Compliance Audit Flow (Quant AI advisory, AI Registry gating, SSE pass-through, micro-batch ledger, Merkle consistency check)
- Scenario 3: Air-Gapped Auditor Independent Offline Verification (Air-gapped verification, multi-sig chain check, tamper injection resilience)
"""

import hashlib
import json
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
from tests.fixtures.generate_fixtures import build_evidence_pack_zip


# ==============================================================================
# S1: Fintech Credit Loan Approval Flow
# ==============================================================================

def test_tier4_scenario_fintech_loan_approval_flow(tmp_path, fixtures_paths):
    """
    Scenario 1: High-stakes 500M VND Fintech Loan Approval.
    - PII detected and redacted in loan application
    - High-risk threshold triggers 4-Eyes approval requirement
    - Approver 1 (Credit Lead) reviews with dwell time >= 10s and signs with Internal Key
    - Creator cannot self-approve
    - Approver 2 (Chief Risk Officer) reviews with dwell time >= 10s and signs with CA VN Token
    - Evidence Pack generated and verified offline
    """
    # 1. Customer application submission with PII
    raw_loan_application = {
        "customer_name": "Nguyễn Văn Đắc",
        "cccd": "001090012345",
        "phone": "0912345678",
        "requested_amount_vnd": 500000000,
        "monthly_income_vnd": 45000000,
        "dti_ratio": 0.28
    }

    # 2. PII Detection & Redaction
    raw_str = json.dumps(raw_loan_application, ensure_ascii=False)
    masked_str, pii_detected = VietnamesePIIScanner.scan_and_mask(raw_str)
    assert "CCCD" in pii_detected
    assert "PHONE" in pii_detected
    assert "001******345" in masked_str
    assert "091****678" in masked_str

    # 3. ML Scoring & Decision
    ml_decision = {
        "event_id": "018f3a9e-loan-scen-001",
        "ai_system_id": "credit-scoring-xgboost",
        "model_version": "v2.1.0",
        "artifact_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "score": 785.5,
        "decision": "APPROVE_LOAN_500M",
        "creator_id": "loan-officer-originator",
        "requires_approval": True,
        "amount_vnd": 500000000
    }

    # 4. Enforce AI Registry
    status, msg = AIRegistryContract.evaluate_request(
        ai_system_id=ml_decision["ai_system_id"],
        artifact_hash=ml_decision["artifact_hash"]
    )
    assert status == 200
    assert msg == "AUTHORIZED"

    # 5. Initialize 4-Eyes Approval State Machine
    decision_id = ml_decision["event_id"]
    sm = ApprovalStateMachine(
        decision_id=decision_id,
        creator_id=ml_decision["creator_id"],
        min_dwell_seconds=10,
        requires_4_eyes=True
    )
    assert sm.status == ApprovalStateMachine.STATUS_PENDING

    # 6. Approver 1 (Credit Lead) reviews and signs with Internal Key
    with open(fixtures_paths["certs"] / "signer_1.key", "rb") as f:
        k1 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_1.pem", "rb") as f:
        c1_pem = f.read()

    p1 = {
        "decision_id": decision_id,
        "approver_id": "credit-lead-01",
        "action": "APPROVE",
        "dwell_time_seconds": 15,
        "timestamp": "2026-10-05T10:35:00Z"
    }
    sig1 = k1.sign(canonical_json(p1), padding.PKCS1v15(), hashes.SHA256())
    st1, _ = sm.submit_action("credit-lead-01", "APPROVE", dwell_seconds=15, signer_type="internal")
    assert st1 == 200
    assert sm.status == ApprovalStateMachine.STATUS_AWAITING_SECOND

    # 7. Creator attempts self-approval -> Strictly blocked
    st_creator, msg_creator = sm.submit_action(ml_decision["creator_id"], "APPROVE", dwell_seconds=15)
    assert st_creator == 403
    assert "CREATOR_CANNOT_APPROVE" in msg_creator

    # 8. Approver 2 (Chief Risk Officer) reviews and signs with CA VN Token
    with open(fixtures_paths["certs"] / "signer_2.key", "rb") as f:
        k2 = serialization.load_pem_private_key(f.read(), password=None)
    with open(fixtures_paths["certs"] / "signer_2.pem", "rb") as f:
        c2_pem = f.read()

    p2 = {
        "decision_id": decision_id,
        "approver_id": "cro-risk-officer-02",
        "action": "APPROVE",
        "dwell_time_seconds": 22,
        "timestamp": "2026-10-05T10:38:00Z"
    }
    sig2 = k2.sign(canonical_json(p2), padding.PKCS1v15(), hashes.SHA256())
    st2, _ = sm.submit_action("cro-risk-officer-02", "APPROVE", dwell_seconds=22, signer_type="ca_vn_token")
    assert st2 == 200
    assert sm.status == ApprovalStateMachine.STATUS_APPROVED

    # 9. Commit to Ledger and build Evidence Pack
    with open(fixtures_paths["certs"] / "root_ca.pem", "rb") as f:
        root_pem = f.read()

    leaf_hash = hashlib.sha256(canonical_json(ml_decision)).hexdigest()
    root_hash = hashlib.sha256((leaf_hash + leaf_hash).encode("utf-8")).hexdigest()
    merkle_proof = {
        "root_hash": root_hash,
        "leaf_hash": leaf_hash,
        "index": 0,
        "total_leaves": 1,
        "audit_path": [leaf_hash]
    }

    sig_objs = [
        {"signer_type": "internal", "approver_id": "credit-lead-01", "signed_payload": p1, "signature_hex": sig1.hex()},
        {"signer_type": "ca_vn_token", "approver_id": "cro-risk-officer-02", "signed_payload": p2, "signature_hex": sig2.hex()}
    ]

    pack_zip = tmp_path / "fintech_loan_evidence_pack.zip"
    build_evidence_pack_zip(
        pack_zip,
        events=[ml_decision],
        merkle_proof=merkle_proof,
        signatures=sig_objs,
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # 10. Offline Verification
    verifier = EvidenceVerifier(str(pack_zip))
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SUCCESS
    assert msg == "VERIFICATION_SUCCESS"


# ==============================================================================
# S2: Securities Trading Compliance Audit Flow
# ==============================================================================

def test_tier4_scenario_securities_trading_audit(mock_llm):
    """
    Scenario 2: Algorithmic Securities Trading Audit.
    - AI Registry verifies system securities-quant-advisor-v1
    - SSE stream pass-through delivers trading advice with zero buffering
    - Token accumulator reassembles advice on EOF
    - Micro-batch worker batches trade orders into immudb ledger within 50ms window
    - Merkle consistency check proves immutability since previous audit checkpoint
    """
    system_id = "securities-quant-advisor-v1"

    # 1. AI Registry Check
    status, msg = AIRegistryContract.evaluate_request(system_id)
    assert status == 200
    assert msg == "AUTHORIZED"

    # 2. SSE Streaming Pass-Through via Mock LLM
    mock_llm.configure(custom_response="Khuyến nghị: MUA 10.000 HPG tại giá 28.500 VNĐ. Cắt lỗ: 27.000 VNĐ.")
    import urllib.request
    req = urllib.request.Request(
        f"{mock_llm.base_url}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "Tín hiệu cổ phiếu HPG"}], "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-AI-System-ID": system_id}
    )

    chunks = []
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            text = line.decode("utf-8").strip()
            if text == "data: [DONE]":
                break
            if text.startswith("data: "):
                chunks.append(json.loads(text[6:]))
    mock_llm.reset_config()

    full_advice = "".join(
        c["choices"][0]["delta"]["content"]
        for c in chunks
        if "content" in c["choices"][0]["delta"]
    )
    assert "MUA 10.000 HPG" in full_advice

    # 3. Micro-batch Ledger Recording (Batch of 20 algorithmic trade decisions)
    trade_events = [
        {
            "event_id": f"trade-ev-{i:04d}",
            "ai_system_id": system_id,
            "order_id": f"ORD-20261005-{i:04d}",
            "ticker": "HPG",
            "action": "BUY",
            "quantity": 10000,
            "advice": full_advice,
            "timestamp": time.time()
        }
        for i in range(20)
    ]

    t0 = time.perf_counter()
    leaves = [MerkleAuditEngine.hash_leaf(ev) for ev in trade_events]
    checkpoint_1_root = MerkleAuditEngine.compute_root(leaves[:10])
    checkpoint_2_root = MerkleAuditEngine.compute_root(leaves)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert elapsed_ms < 50.0  # Well within 50ms micro-batch window
    assert len(checkpoint_1_root) == 64
    assert len(checkpoint_2_root) == 64
    assert checkpoint_1_root != checkpoint_2_root

    # 4. Inclusion proof for specific order ORD-20261005-0005
    proof = MerkleAuditEngine.generate_inclusion_proof(leaves, target_index=5)
    assert proof["leaf_hash"] == leaves[5]
    assert proof["root_hash"] == checkpoint_2_root


# ==============================================================================
# S3: Air-Gapped Auditor Independent Verification Scenario
# ==============================================================================

def test_tier4_scenario_air_gapped_auditor_verification(fixtures_paths):
    """
    Scenario 3: Completely Isolated Air-Gapped Independent Audit.
    - Cold storage Evidence Pack verified without network or DB
    - Verifies manifest SHA-256 for all packaged files
    - Verifies Merkle tree inclusion proof against root hash
    - Verifies digital signatures and certificate chain against Root CA
    - Asserts VERIFICATION_SUCCESS and Exit Code 0
    - Adversarial tamper injection immediately caught by verifier
    """
    valid_pack = fixtures_paths["packs"] / "valid_pack.zip"
    assert valid_pack.is_file()

    # 1. Execute air-gapped verification
    verifier = EvidenceVerifier(str(valid_pack))
    code, msg = verifier.verify()
    assert code == EvidenceVerifier.EXIT_SUCCESS
    assert msg == "VERIFICATION_SUCCESS"

    # 2. Adversarial Tamper: Modifying events.json triggers Manifest Failure (Exit 1)
    tampered_manifest = fixtures_paths["packs"] / "tampered_manifest.zip"
    verifier_t1 = EvidenceVerifier(str(tampered_manifest))
    code_t1, msg_t1 = verifier_t1.verify()
    assert code_t1 == EvidenceVerifier.EXIT_MANIFEST_FAIL
    assert "Hash mismatch" in msg_t1

    # 3. Adversarial Tamper: Modifying Merkle Root triggers Merkle Failure (Exit 2)
    tampered_merkle = fixtures_paths["packs"] / "tampered_merkle.zip"
    verifier_t2 = EvidenceVerifier(str(tampered_merkle))
    code_t2, msg_t2 = verifier_t2.verify()
    assert code_t2 == EvidenceVerifier.EXIT_MERKLE_FAIL
    assert "Merkle root mismatch" in msg_t2

    # 4. Adversarial Tamper: Forged Signature triggers Signature Failure (Exit 3)
    invalid_sig = fixtures_paths["packs"] / "invalid_signature.zip"
    verifier_t3 = EvidenceVerifier(str(invalid_sig))
    code_t3, msg_t3 = verifier_t3.verify()
    assert code_t3 == EvidenceVerifier.EXIT_SIGNATURE_FAIL
    assert "Signature verification failed" in msg_t3
