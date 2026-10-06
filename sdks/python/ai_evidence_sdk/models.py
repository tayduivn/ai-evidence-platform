"""Core data models and configurations for the AI Evidence SDK."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from ai_evidence_sdk.approval.states import ApprovalStatus, ApprovalAction
from ai_evidence_sdk.approval.result import ApprovalResult, ApproverRecord


class DropPolicy(str, Enum):
    """Queue overflow policy when buffer reaches max_queue_size."""

    DROP_OLDEST = "drop_oldest"
    DROP_NEWEST = "drop_newest"


@dataclass
class FeatureImpact:
    """Contribution metric of an individual feature in model explainability."""

    feature: str
    importance: float
    contribution: Optional[str] = None
    value: Optional[Any] = None


@dataclass
class MLExplanation:
    """Explainability metadata (e.g. SHAP values, feature importance)."""

    method: str  # e.g. "SHAP_TreeExplainer"
    top_features: List[FeatureImpact] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "top_features": [asdict(f) for f in self.top_features],
        }


@dataclass
class MLDecisionEvent:
    """Decision event payload for machine learning inference tracking."""

    ai_system_id: str
    score: float
    model_version: Optional[str] = None
    artifact_hash: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    decision: Optional[str] = None
    explanation: Optional[Union[MLExplanation, Dict[str, Any]]] = None
    correlation_id: Optional[str] = None
    requires_approval: bool = False
    creator_id: Optional[str] = None
    webhook_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes event to dictionary matching Gateway API schema."""
        data: Dict[str, Any] = {
            "ai_system_id": self.ai_system_id,
            "score": self.score,
            "requires_approval": self.requires_approval,
        }
        if self.model_version is not None:
            data["model_version"] = self.model_version
        if self.artifact_hash is not None:
            data["artifact_hash"] = self.artifact_hash
        if self.features is not None:
            data["features"] = self.features
        if self.decision is not None:
            data["decision"] = self.decision
        if self.explanation is not None:
            if isinstance(self.explanation, MLExplanation):
                data["explanation"] = self.explanation.to_dict()
            else:
                data["explanation"] = self.explanation
        if self.correlation_id is not None:
            data["correlation_id"] = self.correlation_id
        if self.creator_id is not None:
            data["creator_id"] = self.creator_id
        if self.webhook_url is not None:
            data["webhook_url"] = self.webhook_url
        return data


@dataclass
class ClientConfig:
    """Configuration settings for EvidenceClient."""

    ingest_url: str = "http://127.0.0.1:8080/api/v1/ml/ingest"
    max_queue_size: int = 10000
    drop_policy: DropPolicy = DropPolicy.DROP_OLDEST
    batch_size: int = 50
    flush_interval_sec: float = 0.05
    http_timeout_sec: float = 3.0
    max_retries: int = 5
    base_backoff_sec: float = 0.1
    max_backoff_sec: float = 5.0
    api_key: Optional[str] = None
    auto_flush_on_exit: bool = True
