"""
Shared Pytest Configuration and E2E Test Fixtures.
Provides:
- Embedded Mock LLM background server fixture
- Path fixtures for certificates, payloads, and evidence packs
- Contract simulators for progressive testability (PII, Registry, Merkle, Signer, Approval, SDKs)
- SSE stream consumer utilities
"""

import hashlib
import json
import os
import queue
import re
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import pytest

from services.mock_llm.server import MockLLMServer
from tests.e2e.verifier_oracle import EvidenceVerifier, canonical_json

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
CERTS_DIR = FIXTURES_DIR / "certs"
PAYLOADS_DIR = FIXTURES_DIR / "payloads"
PACKS_DIR = FIXTURES_DIR / "evidence_packs"


@pytest.fixture(scope="session")
def mock_llm():
    """Starts a Mock LLM Server in background on an ephemeral port."""
    server = MockLLMServer(host="127.0.0.1", port=0)
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def fixtures_paths():
    return {
        "certs": CERTS_DIR,
        "payloads": PAYLOADS_DIR,
        "packs": PACKS_DIR
    }


# ==============================================================================
# Contract Simulators (Independent Reference Implementations of Platform Contracts)
# ==============================================================================

class VietnamesePIIScanner:
    """Independent Reference Scanner for Vietnamese PII (CCCD, Phone, Bank Account)."""

    # 12-digit CCCD pattern (starts with 0, followed by 11 digits)
    CCCD_REGEX = re.compile(r"\b0\d{11}\b")

    # VN Phone: +84 followed by 9 digits, or 0 followed by 9 digits (starts with 3,5,7,8,9)
    PHONE_REGEX = re.compile(r"(?:\+84[35789]\d{8}|\b0[35789]\d{8})\b")

    # Bank Account: 8 to 16 digits often preceded by keywords like STK, TK, tài khoản
    BANK_REGEX = re.compile(r"(?:STK|TK|tài khoản|account)[\s:]*([0-9]{8,16})", re.IGNORECASE)

    @classmethod
    def scan_and_mask(cls, text: str) -> Tuple[str, List[str]]:
        detected = []
        masked_text = text

        # Mask CCCD: retain first 3 and last 3, mask 6 digits in middle
        def mask_cccd_match(m):
            detected.append("CCCD")
            val = m.group(0)
            return f"{val[:3]}******{val[-3:]}"

        if cls.CCCD_REGEX.search(masked_text):
            masked_text = cls.CCCD_REGEX.sub(mask_cccd_match, masked_text)

        # Mask Phone: retain prefix and last 3 digits
        def mask_phone_match(m):
            detected.append("PHONE")
            val = m.group(0)
            if val.startswith("+84"):
                return f"{val[:5]}****{val[-3:]}"
            return f"{val[:3]}****{val[-3:]}"

        if cls.PHONE_REGEX.search(masked_text):
            masked_text = cls.PHONE_REGEX.sub(mask_phone_match, masked_text)

        # Mask Bank Account
        def mask_bank_match(m):
            detected.append("BANK_ACCOUNT")
            full_match = m.group(0)
            account_num = m.group(1)
            masked_num = f"{account_num[:4]}******{account_num[-4:]}" if len(account_num) >= 8 else "******"
            return full_match.replace(account_num, masked_num)

        if cls.BANK_REGEX.search(masked_text):
            masked_text = cls.BANK_REGEX.sub(mask_bank_match, masked_text)

        return masked_text, sorted(list(set(detected)))


class AIRegistryContract:
    """Independent Reference Validator for AI Registry & Shadow AI Gating."""

    REGISTERED_SYSTEMS = {
        "credit-advisor-v1": {
            "model_version": "gpt-4o-2024-08-06",
            "risk_level": "HIGH",
            "requires_approval": True,
            "expected_prompt_hash": "a1b2c3d4"
        },
        "securities-quant-advisor-v1": {
            "model_version": "gpt-4o",
            "risk_level": "HIGH",
            "requires_approval": False
        },
        "credit-scoring-xgboost": {
            "model_version": "v2.1.0",
            "risk_level": "CRITICAL",
            "artifact_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            "requires_approval": True
        }
    }

    @classmethod
    def evaluate_request(
        cls,
        ai_system_id: Optional[str],
        model_version: Optional[str] = None,
        artifact_hash: Optional[str] = None,
        prompt_hash: Optional[str] = None
    ) -> Tuple[int, str]:
        if not ai_system_id:
            return 403, "Missing X-AI-System-ID header: Shadow AI detected"

        if ai_system_id not in cls.REGISTERED_SYSTEMS:
            return 403, f"Unregistered AI system '{ai_system_id}': Shadow AI rejected"

        spec = cls.REGISTERED_SYSTEMS[ai_system_id]
        if artifact_hash and spec.get("artifact_hash") and artifact_hash != spec["artifact_hash"]:
            return 403, "Artifact hash mismatch: Model tampering detected"

        if prompt_hash and spec.get("expected_prompt_hash") and prompt_hash != spec["expected_prompt_hash"]:
            return 403, "Prompt hash mismatch: Unauthorized prompt modification"

        return 200, "AUTHORIZED"


class MerkleAuditEngine:
    """Independent Merkle Tree Reference Implementation for Audit Proofs."""

    @staticmethod
    def hash_leaf(event_dict: Dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(event_dict)).hexdigest()

    @staticmethod
    def compute_root(leaves: List[str]) -> str:
        if not leaves:
            return hashlib.sha256(b"").hexdigest()
        if len(leaves) == 1:
            return hashlib.sha256((leaves[0] + leaves[0]).encode("utf-8")).hexdigest()

        current = list(leaves)
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)
            current = next_level
        return current[0]

    @classmethod
    def generate_inclusion_proof(cls, leaves: List[str], target_index: int) -> Dict[str, Any]:
        target_leaf = leaves[target_index]
        root = cls.compute_root(leaves)
        sibling = leaves[target_index]  # for single leaf
        return {
            "root_hash": root,
            "leaf_hash": target_leaf,
            "index": target_index,
            "total_leaves": len(leaves),
            "audit_path": [sibling]
        }


class ApprovalStateMachine:
    """State Machine enforcing 4-Eyes separation and Anti-Rubberstamping dwell time."""

    STATUS_PENDING = "PENDING"
    STATUS_AWAITING_SECOND = "AWAITING_SECOND_APPROVAL"
    STATUS_APPROVED = "APPROVED"
    STATUS_REJECTED = "REJECTED"
    STATUS_EXPIRED = "EXPIRED"

    def __init__(self, decision_id: str, creator_id: str, min_dwell_seconds: int = 10, requires_4_eyes: bool = True):
        self.decision_id = decision_id
        self.creator_id = creator_id
        self.min_dwell_seconds = min_dwell_seconds
        self.requires_4_eyes = requires_4_eyes
        self.status = self.STATUS_PENDING
        self.approvals: List[Dict[str, Any]] = []

    def submit_action(self, approver_id: str, action: str, dwell_seconds: int, signer_type: str = "internal") -> Tuple[int, str]:
        if self.status in (self.STATUS_APPROVED, self.STATUS_REJECTED, self.STATUS_EXPIRED):
            return 400, f"Cannot transition from terminal state {self.status}"

        # Creator separation rule
        if approver_id == self.creator_id:
            return 403, "CREATOR_CANNOT_APPROVE: Creator cannot approve their own decision"

        # Dwell time enforcement (anti-rubberstamping)
        if dwell_seconds < self.min_dwell_seconds:
            return 422, f"DWELL_TIME_NOT_MET: Viewing duration {dwell_seconds}s < required {self.min_dwell_seconds}s"

        if action == "REJECT":
            self.status = self.STATUS_REJECTED
            return 200, "Decision REJECTED"

        if action != "APPROVE":
            return 400, f"Invalid action: {action}"

        # Duplicate approver rule
        existing_approvers = [a["approver_id"] for a in self.approvals]
        if approver_id in existing_approvers:
            return 400, "DUPLICATE_APPROVER: Distinct approver required for second approval"

        self.approvals.append({
            "approver_id": approver_id,
            "dwell_seconds": dwell_seconds,
            "signer_type": signer_type,
            "timestamp": time.time()
        })

        if self.requires_4_eyes:
            if len(self.approvals) == 1:
                self.status = self.STATUS_AWAITING_SECOND
                return 200, "Awaiting second approval"
            elif len(self.approvals) >= 2:
                self.status = self.STATUS_APPROVED
                return 200, "Decision APPROVED with 4-Eyes confirmation"
        else:
            self.status = self.STATUS_APPROVED
            return 200, "Decision APPROVED"

        return 200, self.status


class MockPythonSDKClient:
    """Reference implementation of Python SDK Client Contract (< 5ms non-blocking)."""

    def __init__(self, ingest_url: str, max_queue_size: int = 1000):
        self.ingest_url = ingest_url
        self.buffer_queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_events = 0
        self.is_running = True
        self.worker = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    def log_decision(self, event_data: Dict[str, Any]) -> bool:
        """Must return in < 5ms without blocking or raising exceptions."""
        start_t = time.perf_counter()
        try:
            self.buffer_queue.put_nowait(event_data)
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            assert duration_ms < 5.0, f"Call exceeded 5ms SLA: {duration_ms}ms"
            return True
        except queue.Full:
            self.dropped_events += 1
            return False

    def request_approval(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Creates approval request and returns tracking decision ID."""
        decision_id = f"dec-ml-{hashlib.md5(canonical_json(event_data)).hexdigest()[:12]}"
        return {
            "status": "PENDING_APPROVAL",
            "decision_id": decision_id,
            "poll_url": f"/api/v1/decisions/{decision_id}/status"
        }

    def _worker_loop(self):
        while self.is_running:
            try:
                item = self.buffer_queue.get(timeout=0.1)
                # simulate processing or delivery attempt
                self.buffer_queue.task_done()
            except queue.Empty:
                continue

    def close(self):
        self.is_running = False
        if self.worker.is_alive():
            self.worker.join(timeout=1.0)
