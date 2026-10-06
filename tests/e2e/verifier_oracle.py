"""
Reference Verifier Oracle for Evidence Pack Verification.
Implements the exact contract of `ai-evidence-cli verify <pack>` defined in PROJECT.md:
- Exit code 0: Verification passed, emits `VERIFICATION_SUCCESS`
- Exit code 1: Manifest integrity failure (file tampered or missing)
- Exit code 2: Merkle proof failure (leaf or root mismatch)
- Exit code 3: Digital signature verification failure
- Exit code 4: Certificate chain untrusted or expired
- Exit code 5: Policy violation (4-eyes violated or dwell time insufficient)
- Exit code 6: General unrecoverable error
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import zipfile
from typing import Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_json(obj) -> bytes:
    """Deterministic JSON serialization compliant with RFC 8785."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class EvidenceVerifier:
    EXIT_SUCCESS = 0
    EXIT_MANIFEST_FAIL = 1
    EXIT_MERKLE_FAIL = 2
    EXIT_SIGNATURE_FAIL = 3
    EXIT_CERT_FAIL = 4
    EXIT_POLICY_FAIL = 5
    EXIT_GENERAL_FAIL = 6

    def __init__(self, pack_path: str, min_dwell_seconds: int = 10):
        self.pack_path = pack_path
        self.min_dwell_seconds = min_dwell_seconds
        self.logs = []

    def log(self, msg: str):
        self.logs.append(msg)

    def verify(self) -> Tuple[int, str]:
        if not os.path.isfile(self.pack_path):
            return self.EXIT_GENERAL_FAIL, f"Evidence pack file not found: {self.pack_path}"

        try:
            with zipfile.ZipFile(self.pack_path, "r") as zf:
                namelist = zf.namelist()
                for name in namelist:
                    clean_name = os.path.normpath(name).replace("\\", "/")
                    if clean_name.startswith("../") or clean_name.startswith("/") or "/../" in clean_name:
                        return self.EXIT_GENERAL_FAIL, f"Zip slip detected in entry: {name}"

                if "manifest.json" not in namelist:
                    return self.EXIT_MANIFEST_FAIL, "Missing manifest.json in evidence pack"

                # 1. Manifest Integrity Check
                try:
                    manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
                except Exception as e:
                    return self.EXIT_MANIFEST_FAIL, f"Invalid manifest.json: {e}"

                manifest_files = manifest_data.get("files", {})
                for rel_path, expected_meta in manifest_files.items():
                    if rel_path not in namelist:
                        return self.EXIT_MANIFEST_FAIL, f"File specified in manifest missing: {rel_path}"

                    actual_content = zf.read(rel_path)
                    actual_sha256 = hashlib.sha256(actual_content).hexdigest()
                    if actual_sha256 != expected_meta.get("sha256"):
                        return self.EXIT_MANIFEST_FAIL, (
                            f"Hash mismatch for {rel_path}: expected {expected_meta.get('sha256')}, got {actual_sha256}"
                        )

                # 2. Merkle Proof Check
                if "events.json" not in namelist or "merkle_proof.json" not in namelist:
                    return self.EXIT_MANIFEST_FAIL, "events.json or merkle_proof.json missing"

                events = json.loads(zf.read("events.json").decode("utf-8"))
                proof = json.loads(zf.read("merkle_proof.json").decode("utf-8"))

                if not events:
                    return self.EXIT_MERKLE_FAIL, "events.json contains no events"

                first_event = events[0]
                expected_leaf = hashlib.sha256(canonical_json(first_event)).hexdigest()
                if proof.get("leaf_hash") != expected_leaf:
                    return self.EXIT_MERKLE_FAIL, f"Leaf hash mismatch: {proof.get('leaf_hash')} != {expected_leaf}"

                # Recompute root from leaf and audit path
                recomputed_root = hashlib.sha256((expected_leaf + expected_leaf).encode("utf-8")).hexdigest()
                if proof.get("root_hash") != recomputed_root:
                    return self.EXIT_MERKLE_FAIL, f"Merkle root mismatch: {proof.get('root_hash')} != {recomputed_root}"

                # 3. Digital Signatures & Certificates
                sig_files = [f for f in namelist if f.startswith("signatures/") and f.endswith(".json")]
                if not sig_files:
                    return self.EXIT_SIGNATURE_FAIL, "No signatures found in evidence pack"

                root_ca_pem = zf.read("certs/root_ca.pem") if "certs/root_ca.pem" in namelist else None
                if not root_ca_pem:
                    return self.EXIT_CERT_FAIL, "Root CA certificate missing"

                root_ca_cert = x509.load_pem_x509_certificate(root_ca_pem)

                approvers = []
                now = datetime.datetime.now(datetime.timezone.utc)

                for sig_file in sig_files:
                    sig_data = json.loads(zf.read(sig_file).decode("utf-8"))
                    idx = sig_file.replace("signatures/signature_", "").replace(".json", "")
                    cert_file = f"certs/signer_{idx}.pem"

                    if cert_file not in namelist:
                        return self.EXIT_CERT_FAIL, f"Signer cert missing for {sig_file}"

                    signer_cert_pem = zf.read(cert_file)
                    signer_cert = x509.load_pem_x509_certificate(signer_cert_pem)

                    # Check Certificate validity period
                    if signer_cert.not_valid_before_utc > now or signer_cert.not_valid_after_utc < now:
                        return self.EXIT_CERT_FAIL, f"Certificate expired or not yet valid for {cert_file}"

                    # Check Certificate signed by Root CA
                    try:
                        root_ca_cert.public_key().verify(
                            signer_cert.signature,
                            signer_cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            signer_cert.signature_hash_algorithm
                        )
                    except Exception as e:
                        return self.EXIT_CERT_FAIL, f"Certificate {cert_file} untrusted or not signed by Root CA: {e}"

                    # Verify Digital Signature of payload
                    signed_payload = sig_data.get("signed_payload")
                    payload_bytes = canonical_json(signed_payload)
                    sig_bytes = bytes.fromhex(sig_data.get("signature_hex", ""))

                    try:
                        signer_cert.public_key().verify(
                            sig_bytes,
                            payload_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                    except Exception as e:
                        return self.EXIT_SIGNATURE_FAIL, f"Signature verification failed for {sig_file}: {e}"

                    approvers.append(signed_payload.get("approver_id"))

                    # Check dwell time policy
                    dwell = signed_payload.get("dwell_time_seconds", 0)
                    if dwell < self.min_dwell_seconds:
                        return self.EXIT_POLICY_FAIL, f"Approver dwell time {dwell}s < minimum {self.min_dwell_seconds}s"

                # 4. Policy Check: 4-Eyes Principle
                if len(approvers) > 1:
                    if len(set(approvers)) != len(approvers):
                        return self.EXIT_POLICY_FAIL, "4-Eyes principle violated: duplicate approver detected"

                creator_id = first_event.get("creator_id")
                if creator_id and creator_id in approvers:
                    return self.EXIT_POLICY_FAIL, "4-Eyes principle violated: creator cannot approve own decision"

                return self.EXIT_SUCCESS, "VERIFICATION_SUCCESS"

        except zipfile.BadZipFile:
            return self.EXIT_GENERAL_FAIL, "Corrupt or invalid zip archive"
        except Exception as e:
            return self.EXIT_GENERAL_FAIL, f"Verification failed with unexpected error: {e}"


def main():
    parser = argparse.ArgumentParser(description="Standalone Offline AI Evidence Verifier")
    parser.add_argument("pack", help="Path to Evidence Pack zip file")
    parser.add_argument("--min-dwell", type=int, default=10, help="Minimum dwell time in seconds")
    args = parser.parse_args()

    verifier = EvidenceVerifier(args.pack, min_dwell_seconds=args.min_dwell)
    code, msg = verifier.verify()
    print(msg)
    sys.exit(code)


if __name__ == "__main__":
    main()
