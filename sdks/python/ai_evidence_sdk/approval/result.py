"""Approval result and audit record models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from ai_evidence_sdk.approval.states import ApprovalStatus


@dataclass
class ApproverRecord:
    """Individual human review action record from audit trail."""

    approver_id: str
    role: Optional[str] = None
    action: str = ""
    dwell_seconds: int = 0
    signer_type: Optional[str] = None
    signature_hex: Optional[str] = None
    comment: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class ApprovalResult:
    """Outcome of waiting for or polling a decision."""

    decision_id: str
    status: Union[ApprovalStatus, str]
    is_approved: bool
    correlation_id: Optional[str] = None
    approvals: List[ApproverRecord] = field(default_factory=list)
    signature_hex: Optional[str] = None
    rejection_reason: Optional[str] = None
    timed_out: bool = False
    elapsed_seconds: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts result to standard dictionary."""
        return {
            "decision_id": self.decision_id,
            "status": str(self.status),
            "is_approved": self.is_approved,
            "correlation_id": self.correlation_id,
            "signature_hex": self.signature_hex,
            "rejection_reason": self.rejection_reason,
            "timed_out": self.timed_out,
            "elapsed_seconds": self.elapsed_seconds,
            "raw_data": self.raw_data,
        }
