"""
Fixture Generator for AI Evidence Platform E2E Tests.
Generates:
- Self-signed Root CA and subordinate signer X.509 certificates
- Untrusted CA and expired certificates for negative testing
- 50KB synthetic payload fixture
- Vietnamese PII test dataset
- Valid and tampered Evidence Pack ZIP archives for CLI verification tests
"""

import datetime
import hashlib
import json
import os
import zipfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
PAYLOADS_DIR = BASE_DIR / "payloads"
PACKS_DIR = BASE_DIR / "evidence_packs"


def canonical_json(obj) -> bytes:
    """Deterministic JSON serialization compliant with RFC 8785."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_certificates():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Root CA Key & Cert
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI Evidence Platform CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AI Evidence Root CA v1"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    with open(CERTS_DIR / "root_ca.key", "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERTS_DIR / "root_ca.pem", "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))

    # Helper for signing subordinate cert
    def issue_cert(common_name: str, valid_days: int = 365, expired: bool = False, ca_key=root_key, ca_cert=root_cert):
        signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Audit Dept"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        if expired:
            start_date = now - datetime.timedelta(days=400)
            end_date = now - datetime.timedelta(days=30)
        else:
            start_date = now - datetime.timedelta(days=1)
            end_date = now + datetime.timedelta(days=valid_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(signer_name)
            .issuer_name(ca_cert.subject)
            .public_key(signer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start_date)
            .not_valid_after(end_date)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        return signer_key, cert

    # 2. Signer 1 (Approver 1)
    k1, c1 = issue_cert("Nguyen Van Approver (Credit Lead)")
    with open(CERTS_DIR / "signer_1.key", "wb") as f:
        f.write(k1.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERTS_DIR / "signer_1.pem", "wb") as f:
        f.write(c1.public_bytes(serialization.Encoding.PEM))

    # 3. Signer 2 (Approver 2)
    k2, c2 = issue_cert("Tran Thi Risk Officer (4-Eyes Auditor)")
    with open(CERTS_DIR / "signer_2.key", "wb") as f:
        f.write(k2.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERTS_DIR / "signer_2.pem", "wb") as f:
        f.write(c2.public_bytes(serialization.Encoding.PEM))

    # 4. Expired Signer
    k_exp, c_exp = issue_cert("Expired Officer", expired=True)
    with open(CERTS_DIR / "expired_signer.key", "wb") as f:
        f.write(k_exp.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERTS_DIR / "expired_signer.pem", "wb") as f:
        f.write(c_exp.public_bytes(serialization.Encoding.PEM))

    # 5. Untrusted Rogue CA & Signer
    rogue_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Untrusted CA"),
    ])
    rogue_root_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_root_name)
        .issuer_name(rogue_root_name)
        .public_key(rogue_root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_root_key, hashes.SHA256())
    )
    with open(CERTS_DIR / "untrusted_ca.pem", "wb") as f:
        f.write(rogue_root_cert.public_bytes(serialization.Encoding.PEM))

    k_untrusted, c_untrusted = issue_cert("Untrusted Attacker", ca_key=rogue_root_key, ca_cert=rogue_root_cert)
    with open(CERTS_DIR / "untrusted_signer.key", "wb") as f:
        f.write(k_untrusted.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERTS_DIR / "untrusted_signer.pem", "wb") as f:
        f.write(c_untrusted.public_bytes(serialization.Encoding.PEM))

    return {
        "root_key": root_key, "root_cert": root_cert,
        "k1": k1, "c1": c1,
        "k2": k2, "c2": c2,
        "k_exp": k_exp, "c_exp": c_exp,
        "k_untrusted": k_untrusted, "c_untrusted": c_untrusted
    }


def generate_payloads():
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 50KB Payload
    base_text = "Hệ thống AI phân tích đánh giá tín nhiệm doanh nghiệp tài chính. " * 30
    items = []
    for i in range(250):
        items.append({
            "record_id": f"REC-{i:05d}",
            "description": f"Phân tích chỉ số tài chính quý {i % 4 + 1}: {base_text[:120]}",
            "score": 750 + (i % 50),
            "flags": ["STANDARD", "AUDITED"]
        })
    big_payload = {
        "model": "vietnamese-finance-llm-v1",
        "messages": [
            {"role": "system", "content": "Bạn là chuyên gia thẩm định rủi ro tài chính ngân hàng."},
            {"role": "user", "content": json.dumps(items, ensure_ascii=False)}
        ],
        "metadata": {"batch_id": "BATCH-50KB-BENCHMARK"}
    }
    raw_json = json.dumps(big_payload, ensure_ascii=False)
    # Ensure it reaches ~50KB
    target_bytes = 51200
    if len(raw_json.encode("utf-8")) < target_bytes:
        padding_len = target_bytes - len(raw_json.encode("utf-8")) + 200
        big_payload["padding"] = "X" * padding_len
        raw_json = json.dumps(big_payload, ensure_ascii=False)

    with open(PAYLOADS_DIR / "payload_50kb.json", "w", encoding="utf-8") as f:
        f.write(raw_json)

    # 2. Vietnamese PII Samples
    pii_samples = {
        "cccd": [
            {"raw": "001090012345", "valid": True, "masked": "001******345"},
            {"raw": "079085009876", "valid": True, "masked": "079******876"},
            {"raw": "038192004561", "valid": True, "masked": "038******561"},
            {"raw": "12345678", "valid": False, "note": "Too short (8 digits)"},
            {"raw": "0010900123456", "valid": False, "note": "Too long (13 digits)"},
            {"raw": "00109001234A", "valid": False, "note": "Contains letter"}
        ],
        "phone": [
            {"raw": "0912345678", "valid": True, "masked": "091****678"},
            {"raw": "0988776655", "valid": True, "masked": "098****655"},
            {"raw": "+84903112233", "valid": True, "masked": "+8490****233"},
            {"raw": "0868999888", "valid": True, "masked": "086****888"},
            {"raw": "012345678", "valid": False, "note": "Invalid prefix"},
            {"raw": "0912345", "valid": False, "note": "Too short"}
        ],
        "bank_account": [
            {"raw": "19034567890123", "bank": "Techcombank", "masked": "1903******0123"},
            {"raw": "0071001234567", "bank": "Vietcombank", "masked": "0071******4567"},
            {"raw": "101889998888", "bank": "VietinBank", "masked": "1018******8888"}
        ]
    }
    with open(PAYLOADS_DIR / "pii_samples.json", "w", encoding="utf-8") as f:
        json.dump(pii_samples, f, indent=2, ensure_ascii=False)

    # 3. ML Ingest Sample (Credit Loan)
    ml_loan = {
        "ai_system_id": "credit-scoring-xgboost",
        "model_version": "v2.1.0",
        "artifact_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "features": {
            "monthly_income_vnd": 45000000,
            "debt_to_income_ratio": 0.28,
            "credit_history_months": 36,
            "late_payment_count": 0,
            "collateral_value_vnd": 1200000000
        },
        "score": 785.5,
        "decision": "APPROVE_LOAN_500M",
        "explanation": {
            "method": "SHAP_TreeExplainer",
            "top_features": [
                {"feature": "monthly_income_vnd", "importance": 0.42, "contribution": "+65pts"},
                {"feature": "debt_to_income_ratio", "importance": 0.31, "contribution": "+40pts"},
                {"feature": "late_payment_count", "importance": 0.18, "contribution": "+25pts"}
            ]
        },
        "correlation_id": "tx-fintech-loan-88912",
        "requires_approval": True,
        "creator_id": "ml-system-credit-scoring"
    }
    with open(PAYLOADS_DIR / "ml_loan_request.json", "w", encoding="utf-8") as f:
        json.dump(ml_loan, f, indent=2, ensure_ascii=False)


def build_evidence_pack_zip(target_zip: Path, events, merkle_proof, signatures, certs, root_ca_pem, rfc3161_tsr=b"MOCK_RFC3161_DER_TST_TOKEN"):
    """Creates an Evidence Pack zip bundle matching the architecture contract."""
    files_to_pack = {}

    events_bytes = canonical_json(events)
    files_to_pack["events.json"] = events_bytes

    merkle_bytes = canonical_json(merkle_proof)
    files_to_pack["merkle_proof.json"] = merkle_bytes

    for i, sig in enumerate(signatures, 1):
        files_to_pack[f"signatures/signature_{i}.json"] = canonical_json(sig)

    for i, cert in enumerate(certs, 1):
        files_to_pack[f"certs/signer_{i}.pem"] = cert

    files_to_pack["certs/root_ca.pem"] = root_ca_pem
    files_to_pack["anchor/rfc3161_timestamp.tsr"] = rfc3161_tsr

    # Build manifest.json with SHA-256 of all files
    manifest_entries = {}
    for path, content in files_to_pack.items():
        manifest_entries[path] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content)
        }

    manifest = {
        "version": "1.0",
        "decision_id": events[0]["event_id"] if events else "dec-unknown",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "root_hash": merkle_proof.get("root_hash", ""),
        "files": manifest_entries
    }
    manifest_bytes = canonical_json(manifest)

    # Write to zip
    with zipfile.ZipFile(target_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        for path, content in files_to_pack.items():
            zf.writestr(path, content)


def generate_evidence_packs(certs_data):
    PACKS_DIR.mkdir(parents=True, exist_ok=True)
    k1 = certs_data["k1"]
    c1 = certs_data["c1"]
    k2 = certs_data["k2"]
    c2 = certs_data["c2"]
    root_pem = certs_data["root_cert"].public_bytes(serialization.Encoding.PEM)

    event_id = "018f3a9e-4e89-7b21-9921-3a81289128aa"
    decision_record = {
        "event_id": event_id,
        "correlation_id": "tx-corr-98214",
        "ai_system_id": "credit-advisor-v1",
        "system_type": "llm",
        "model_version": "gpt-4o-2024-08-06",
        "timestamp": "2026-10-05T10:30:00.123456Z",
        "input_payload": json.dumps({"prompt": "Khách hàng CCCD 001090012345 cần vay 500tr"}, ensure_ascii=False),
        "output_payload": json.dumps({"response": "Đã tiếp nhận hồ sơ vay và phê duyệt."}, ensure_ascii=False),
        "input_masked": json.dumps({"prompt": "Khách hàng CCCD 001******345 cần vay 500tr"}, ensure_ascii=False),
        "output_masked": json.dumps({"response": "Đã tiếp nhận hồ sơ vay và phê duyệt."}, ensure_ascii=False),
        "pii_detected": ["CCCD"],
        "tokens_usage": {"prompt_tokens": 18, "completion_tokens": 12, "total_tokens": 30},
        "latency_ms": 284,
        "status": "APPROVED",
        "dwell_time_seconds": 15,
        "approvers": ["approver-user-01", "approver-user-02"]
    }
    events = [decision_record]

    # Calculate Merkle leaf & root
    leaf_hash = hashlib.sha256(canonical_json(decision_record)).hexdigest()
    # Simple single-leaf / 2-leaf Merkle tree
    root_hash = hashlib.sha256((leaf_hash + leaf_hash).encode("utf-8")).hexdigest()
    merkle_proof = {
        "root_hash": root_hash,
        "leaf_hash": leaf_hash,
        "index": 0,
        "total_leaves": 1,
        "audit_path": [leaf_hash]
    }

    # Signed payload for Approver 1
    signed_payload_1 = {
        "decision_id": event_id,
        "approver_id": "approver-user-01",
        "action": "APPROVE",
        "dwell_time_seconds": 15,
        "timestamp": "2026-10-05T10:35:00Z",
        "content_hash": hashlib.sha256(decision_record["output_payload"].encode("utf-8")).hexdigest()
    }
    payload_1_bytes = canonical_json(signed_payload_1)
    sig_1_raw = k1.sign(payload_1_bytes, padding.PKCS1v15(), hashes.SHA256())
    sig_1_obj = {
        "signer_type": "internal",
        "approver_id": "approver-user-01",
        "signed_payload": signed_payload_1,
        "signature_hex": sig_1_raw.hex(),
        "algorithm": "SHA256withRSA"
    }

    # Signed payload for Approver 2 (4-eyes)
    signed_payload_2 = {
        "decision_id": event_id,
        "approver_id": "approver-user-02",
        "action": "APPROVE",
        "dwell_time_seconds": 20,
        "timestamp": "2026-10-05T10:36:00Z",
        "content_hash": hashlib.sha256(decision_record["output_payload"].encode("utf-8")).hexdigest()
    }
    payload_2_bytes = canonical_json(signed_payload_2)
    sig_2_raw = k2.sign(payload_2_bytes, padding.PKCS1v15(), hashes.SHA256())
    sig_2_obj = {
        "signer_type": "ca_vn_token",
        "approver_id": "approver-user-02",
        "signed_payload": signed_payload_2,
        "signature_hex": sig_2_raw.hex(),
        "algorithm": "SHA256withRSA"
    }

    c1_pem = c1.public_bytes(serialization.Encoding.PEM)
    c2_pem = c2.public_bytes(serialization.Encoding.PEM)

    # 1. Valid Pack (Exit Code 0)
    build_evidence_pack_zip(
        PACKS_DIR / "valid_pack.zip",
        events=events,
        merkle_proof=merkle_proof,
        signatures=[sig_1_obj, sig_2_obj],
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # 2. Tampered Manifest Pack (Exit Code 1)
    # Manifest lists wrong sha256 for events.json
    build_evidence_pack_zip(
        PACKS_DIR / "tampered_manifest.zip",
        events=events,
        merkle_proof=merkle_proof,
        signatures=[sig_1_obj, sig_2_obj],
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )
    # Corrupt events.json inside zip without updating manifest
    with zipfile.ZipFile(PACKS_DIR / "tampered_manifest.zip", "r") as zr:
        extracted = {name: zr.read(name) for name in zr.namelist()}
    extracted["events.json"] = extracted["events.json"] + b"/* TAMPERED BY ATTACKER */"
    with zipfile.ZipFile(PACKS_DIR / "tampered_manifest.zip", "w") as zw:
        for name, data in extracted.items():
            zw.writestr(name, data)

    # 3. Corrupted Merkle Proof (Exit Code 2)
    bad_merkle = dict(merkle_proof)
    bad_merkle["root_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    build_evidence_pack_zip(
        PACKS_DIR / "tampered_merkle.zip",
        events=events,
        merkle_proof=bad_merkle,
        signatures=[sig_1_obj, sig_2_obj],
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # 4. Invalid Digital Signature (Exit Code 3)
    bad_sig_1 = dict(sig_1_obj)
    # flip byte in signature hex
    bad_sig_1["signature_hex"] = "aa" + sig_1_obj["signature_hex"][2:]
    build_evidence_pack_zip(
        PACKS_DIR / "invalid_signature.zip",
        events=events,
        merkle_proof=merkle_proof,
        signatures=[bad_sig_1, sig_2_obj],
        certs=[c1_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # 5. Untrusted Certificate Chain (Exit Code 4)
    untrusted_pem = certs_data["c_untrusted"].public_bytes(serialization.Encoding.PEM)
    build_evidence_pack_zip(
        PACKS_DIR / "untrusted_cert.zip",
        events=events,
        merkle_proof=merkle_proof,
        signatures=[sig_1_obj, sig_2_obj],
        certs=[untrusted_pem, c2_pem],
        root_ca_pem=root_pem
    )

    # 6. Policy Violation: 4-Eyes Violated (Exit Code 5)
    # Same approver (approver-user-01) signs both times with their own valid key and cert
    bad_policy_payload_2 = {
        "decision_id": event_id,
        "approver_id": "approver-user-01",  # Same approver ID as signature 1
        "action": "APPROVE",
        "dwell_time_seconds": 20,
        "timestamp": "2026-10-05T10:36:00Z",
        "content_hash": hashlib.sha256(decision_record["output_payload"].encode("utf-8")).hexdigest()
    }
    payload_bad_bytes = canonical_json(bad_policy_payload_2)
    sig_bad_raw = k1.sign(payload_bad_bytes, padding.PKCS1v15(), hashes.SHA256())
    bad_policy_sig_2 = {
        "signer_type": "internal",
        "approver_id": "approver-user-01",
        "signed_payload": bad_policy_payload_2,
        "signature_hex": sig_bad_raw.hex(),
        "algorithm": "SHA256withRSA"
    }
    build_evidence_pack_zip(
        PACKS_DIR / "policy_violation_pack.zip",
        events=events,
        merkle_proof=merkle_proof,
        signatures=[sig_1_obj, bad_policy_sig_2],
        certs=[c1_pem, c1_pem],  # Both use c1 cert
        root_ca_pem=root_pem
    )

    # 7. Corrupted Archive (Non-zip byte garbage)
    with open(PACKS_DIR / "corrupt_archive.zip", "wb") as f:
        f.write(b"NOT_A_VALID_ZIP_FILE_STREAM_GARBAGE_1234567890")


def main():
    print("Generating certificates...")
    certs_data = generate_certificates()
    print("Generating payloads...")
    generate_payloads()
    print("Generating evidence packs...")
    generate_evidence_packs(certs_data)
    print("All fixtures generated successfully.")


if __name__ == "__main__":
    main()
