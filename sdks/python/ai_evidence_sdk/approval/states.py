"""Approval lifecycle state enums."""

from enum import Enum


class ApprovalStatus(str, Enum):
    """Lifecycle states for human-in-the-loop decisions."""

    PENDING = "PENDING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    AWAITING_SECOND_APPROVAL = "AWAITING_SECOND_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

    def is_terminal(self) -> bool:
        """Returns True if this status is a terminal resolution state."""
        return self in (
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
            ApprovalStatus.EXPIRED,
        )

    def is_pending(self) -> bool:
        """Returns True if the decision is still waiting for review."""
        return self in (
            ApprovalStatus.PENDING,
            ApprovalStatus.PENDING_APPROVAL,
            ApprovalStatus.AWAITING_SECOND_APPROVAL,
        )


class ApprovalAction(str, Enum):
    """Actions performed by human reviewers."""

    APPROVE = "APPROVE"
    REJECT = "REJECT"
