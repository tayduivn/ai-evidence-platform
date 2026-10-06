"""Unit tests for models and schemas."""

import pytest

from ai_evidence_sdk.models import (
    ApprovalAction,
    ApprovalResult,
    ApprovalStatus,
    ApproverRecord,
    ClientConfig,
    DropPolicy,
    FeatureImpact,
    MLDecisionEvent,
    MLExplanation,
)


def test_ml_decision_event_serialization():
    impact1 = FeatureImpact(feature="debt_ratio", importance=0.42, contribution="negative", value=0.28)
    impact2 = FeatureImpact(feature="income", importance=0.35, contribution="positive", value=45000000)
    expl = MLExplanation(method="SHAP_TreeExplainer", top_features=[impact1, impact2])

    event = MLDecisionEvent(
        ai_system_id="credit-scoring-xgboost",
        score=745.5,
        model_version="v2.1.0",
        artifact_hash="abc123hash",
        features={"income": 45000000, "debt_ratio": 0.28},
        decision="APPROVE_LOAN_500M",
        explanation=expl,
        correlation_id="corr-tx-123",
        requires_approval=True,
        creator_id="analyst-99",
    )

    data = event.to_dict()
    assert data["ai_system_id"] == "credit-scoring-xgboost"
    assert data["score"] == 745.5
    assert data["requires_approval"] is True
    assert data["model_version"] == "v2.1.0"
    assert data["artifact_hash"] == "abc123hash"
    assert data["features"]["income"] == 45000000
    assert data["explanation"]["method"] == "SHAP_TreeExplainer"
    assert len(data["explanation"]["top_features"]) == 2
    assert data["explanation"]["top_features"][0]["feature"] == "debt_ratio"


def test_approval_status_helpers():
    assert ApprovalStatus.APPROVED.is_terminal() is True
    assert ApprovalStatus.REJECTED.is_terminal() is True
    assert ApprovalStatus.EXPIRED.is_terminal() is True
    assert ApprovalStatus.PENDING.is_terminal() is False
    assert ApprovalStatus.PENDING_APPROVAL.is_terminal() is False
    assert ApprovalStatus.AWAITING_SECOND_APPROVAL.is_terminal() is False

    assert ApprovalStatus.PENDING.is_pending() is True
    assert ApprovalStatus.AWAITING_SECOND_APPROVAL.is_pending() is True
    assert ApprovalStatus.APPROVED.is_pending() is False


def test_approval_result_model():
    rec = ApproverRecord(
        approver_id="u-compliance-1",
        role="risk_officer",
        action="APPROVE",
        dwell_seconds=12,
        signer_type="internal",
        signature_hex="beef42",
        comment="Approved per guidelines",
    )
    res = ApprovalResult(
        decision_id="dec-123",
        status=ApprovalStatus.APPROVED,
        is_approved=True,
        correlation_id="corr-1",
        approvals=[rec],
        signature_hex="beef42",
        elapsed_seconds=1.5,
    )

    d = res.to_dict()
    assert d["decision_id"] == "dec-123"
    assert d["is_approved"] is True
    assert d["signature_hex"] == "beef42"


def test_client_config_defaults():
    cfg = ClientConfig()
    assert cfg.max_queue_size == 10000
    assert cfg.drop_policy == DropPolicy.DROP_OLDEST
    assert cfg.batch_size == 50
    assert cfg.flush_interval_sec == 0.05
    assert cfg.auto_flush_on_exit is True
