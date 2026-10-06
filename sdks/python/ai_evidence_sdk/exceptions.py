"""Exception hierarchy for the AI Evidence SDK."""

from typing import Any, Dict, List, Optional


class EvidenceSDKError(Exception):
    """Base exception for all AI Evidence SDK errors."""


class ConfigurationError(EvidenceSDKError):
    """Raised when client configuration is invalid or missing required values."""


class NetworkError(EvidenceSDKError):
    """Raised on network transmission or connection failures."""


class NetworkRetriesExhaustedError(NetworkError):
    """Raised when maximum network retry attempts have been exhausted."""


class PIIValidationError(EvidenceSDKError):
    """Raised when sensitive Vietnamese PII is detected and pii_mode is 'block'."""

    def __init__(
        self,
        message: str,
        detected_types: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.detected_types: List[str] = detected_types or []
        self.details: Dict[str, Any] = details or {}


class ApprovalError(EvidenceSDKError):
    """Base exception for approval subsystem errors."""


class ApprovalTimeoutError(ApprovalError):
    """Raised when polling for approval exceeds the configured timeout."""

    def __init__(
        self,
        decision_id: str,
        timeout: float,
        elapsed: float,
        last_status: Optional[str] = None,
    ):
        self.decision_id = decision_id
        self.timeout = timeout
        self.elapsed = elapsed
        self.last_status = last_status
        super().__init__(
            f"Approval timed out for decision '{decision_id}' after {elapsed:.2f}s "
            f"(configured timeout: {timeout:.2f}s, last known status: {last_status})"
        )


class ApprovalRejectedError(ApprovalError):
    """Raised when a decision is formally rejected by an authorized reviewer."""

    def __init__(
        self,
        decision_id: str,
        reason: Optional[str] = None,
        approver_id: Optional[str] = None,
        role: Optional[str] = None,
    ):
        self.decision_id = decision_id
        self.reason = reason
        self.approver_id = approver_id
        self.role = role
        super().__init__(
            f"Decision '{decision_id}' was REJECTED by approver '{approver_id}' (role: {role}). "
            f"Reason: {reason or 'No rejection comment provided'}"
        )


class ApprovalExpiredError(ApprovalError):
    """Raised when a decision ticket reaches EXPIRED state."""

    def __init__(self, decision_id: str, message: Optional[str] = None):
        self.decision_id = decision_id
        super().__init__(message or f"Decision '{decision_id}' has expired.")


class WebhookVerificationError(ApprovalError):
    """Raised when webhook signature verification fails."""
