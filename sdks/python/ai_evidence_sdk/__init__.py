"""
AI Evidence & Accountability Platform Python SDK.
High-performance, non-blocking telemetry and Human-in-the-Loop approval workflows.
"""

from ai_evidence_sdk.approval.handle import ApprovalHandle
from ai_evidence_sdk.approval.poller import ApprovalPoller
from ai_evidence_sdk.approval.result import ApprovalResult, ApproverRecord
from ai_evidence_sdk.approval.states import ApprovalAction, ApprovalStatus
from ai_evidence_sdk.approval.webhook import WebhookReceiver, verify_webhook_signature
from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.client import EvidenceClient
from ai_evidence_sdk.exceptions import (
    ApprovalError,
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalTimeoutError,
    ConfigurationError,
    EvidenceSDKError,
    NetworkError,
    NetworkRetriesExhaustedError,
    PIIValidationError,
    WebhookVerificationError,
)
from ai_evidence_sdk.models import (
    ClientConfig,
    DropPolicy,
    FeatureImpact,
    MLDecisionEvent,
    MLExplanation,
)
from ai_evidence_sdk.pii.scanner import (
    LABEL_BANK_ACCOUNT,
    LABEL_CCCD,
    LABEL_PHONE,
    PIIValidator,
    mask_bank_account,
    mask_cccd,
    mask_phone,
    scan_and_mask,
    scan_dict,
)

__version__ = "0.3.0"

__all__ = [
    # Core Client & Config
    "EvidenceClient",
    "ClientConfig",
    "DropPolicy",
    "BoundedEventQueue",
    # ML Models
    "MLDecisionEvent",
    "MLExplanation",
    "FeatureImpact",
    # Approval Subsystem
    "ApprovalHandle",
    "ApprovalPoller",
    "ApprovalResult",
    "ApproverRecord",
    "ApprovalStatus",
    "ApprovalAction",
    "verify_webhook_signature",
    "WebhookReceiver",
    # PII Protection
    "PIIValidator",
    "scan_and_mask",
    "scan_dict",
    "mask_cccd",
    "mask_phone",
    "mask_bank_account",
    "LABEL_CCCD",
    "LABEL_PHONE",
    "LABEL_BANK_ACCOUNT",
    # Exceptions
    "EvidenceSDKError",
    "ConfigurationError",
    "NetworkError",
    "NetworkRetriesExhaustedError",
    "PIIValidationError",
    "ApprovalError",
    "ApprovalTimeoutError",
    "ApprovalRejectedError",
    "ApprovalExpiredError",
    "WebhookVerificationError",
]
