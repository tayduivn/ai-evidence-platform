"""Approval polling engine for monotonic waiting across decision lifecycle states."""

import logging
import random
import time
from typing import Any, Dict, List, Optional, Union

from ai_evidence_sdk.approval.handle import ApprovalHandle
from ai_evidence_sdk.approval.result import ApprovalResult, ApproverRecord
from ai_evidence_sdk.approval.states import ApprovalStatus
from ai_evidence_sdk.exceptions import (
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalTimeoutError,
    NetworkRetriesExhaustedError,
)

logger = logging.getLogger("ai_evidence_sdk.approval.poller")


class ApprovalPoller:
    """
    Manages adaptive polling and wait loops against Gateway / Approval endpoints.
    Tracks state transitions: PENDING -> AWAITING_SECOND_APPROVAL -> APPROVED / REJECTED / EXPIRED.
    """

    def __init__(self, client: Any):
        self._client = client

    def wait(
        self,
        target: Union[str, ApprovalHandle],
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        backoff_multiplier: float = 1.2,
        max_poll_interval: float = 5.0,
        jitter: bool = True,
        raise_on_timeout: bool = True,
        raise_on_rejection: bool = False,
    ) -> ApprovalResult:
        """
        Polls until the target decision reaches a terminal state (APPROVED, REJECTED, EXPIRED)
        or until the timeout is reached.
        """
        if isinstance(target, ApprovalHandle):
            decision_id = target.decision_id
            poll_url = target.poll_url
        else:
            decision_id = str(target)
            poll_url = f"/api/v1/decisions/{decision_id}/status"

        start_time = time.monotonic()
        deadline = start_time + timeout
        current_interval = max(0.01, poll_interval)
        last_seen_status: Optional[str] = None
        consecutive_net_failures = 0

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            try:
                status_data = self._client._http_get(
                    poll_url, timeout=min(5.0, max(0.5, remaining))
                )
                consecutive_net_failures = 0
            except Exception as e:
                consecutive_net_failures += 1
                if consecutive_net_failures > 3:
                    raise NetworkRetriesExhaustedError(
                        f"Failed {consecutive_net_failures} consecutive poll attempts: {e}"
                    ) from e
                # Transient backoff sleep before retrying
                sleep_sec = min(0.2 * consecutive_net_failures, max(0.01, remaining))
                time.sleep(sleep_sec)
                continue

            status_str = str(status_data.get("status", "")).upper()
            last_seen_status = status_str

            # Update handle if target was an ApprovalHandle
            if isinstance(target, ApprovalHandle):
                target._status = status_str
                target._raw["status"] = status_str

            # Check terminal states
            if status_str == ApprovalStatus.APPROVED.value:
                approvers = self._fetch_approval_audit(decision_id, status_data)
                sig = approvers[-1].signature_hex if approvers else status_data.get("signature_hex")
                return ApprovalResult(
                    decision_id=decision_id,
                    status=ApprovalStatus.APPROVED,
                    is_approved=True,
                    correlation_id=status_data.get("correlation_id"),
                    approvals=approvers,
                    signature_hex=sig,
                    elapsed_seconds=time.monotonic() - start_time,
                    raw_data=status_data,
                )

            elif status_str == ApprovalStatus.REJECTED.value:
                approvers = self._fetch_approval_audit(decision_id, status_data)
                reason = (
                    approvers[-1].comment
                    if approvers and approvers[-1].comment
                    else status_data.get("rejection_reason") or status_data.get("reason")
                )
                approver_id = approvers[-1].approver_id if approvers else None
                role = approvers[-1].role if approvers else None

                if raise_on_rejection:
                    raise ApprovalRejectedError(decision_id, reason, approver_id, role)

                return ApprovalResult(
                    decision_id=decision_id,
                    status=ApprovalStatus.REJECTED,
                    is_approved=False,
                    correlation_id=status_data.get("correlation_id"),
                    approvals=approvers,
                    rejection_reason=reason,
                    elapsed_seconds=time.monotonic() - start_time,
                    raw_data=status_data,
                )

            elif status_str == ApprovalStatus.EXPIRED.value:
                return ApprovalResult(
                    decision_id=decision_id,
                    status=ApprovalStatus.EXPIRED,
                    is_approved=False,
                    correlation_id=status_data.get("correlation_id"),
                    elapsed_seconds=time.monotonic() - start_time,
                    raw_data=status_data,
                )

            # In-Flight: PENDING, PENDING_APPROVAL, AWAITING_SECOND_APPROVAL
            sleep_duration = min(current_interval, max_poll_interval)
            if jitter:
                sleep_duration *= 1.0 + random.uniform(-0.1, 0.1)

            remaining_after_calc = deadline - time.monotonic()
            sleep_duration = min(sleep_duration, remaining_after_calc)
            if sleep_duration > 0:
                time.sleep(sleep_duration)

            current_interval *= backoff_multiplier

        # Deadline exceeded
        elapsed = time.monotonic() - start_time
        if raise_on_timeout:
            raise ApprovalTimeoutError(decision_id, timeout, elapsed, last_seen_status)

        return ApprovalResult(
            decision_id=decision_id,
            status=ApprovalStatus.EXPIRED,
            is_approved=False,
            timed_out=True,
            elapsed_seconds=elapsed,
            raw_data={"last_status": last_seen_status},
        )

    def _fetch_approval_audit(
        self, decision_id: str, status_data: Dict[str, Any]
    ) -> List[ApproverRecord]:
        """Attempts to fetch detailed approval history from approvals API if available."""
        # First check if approvals list is already embedded in status response
        history = status_data.get("approval_history") or status_data.get("approvals") or []
        if not history:
            try:
                detail = self._client._http_get(f"/api/v1/approvals/{decision_id}", timeout=2.0)
                history = detail.get("approval_history") or detail.get("approvals") or []
            except Exception:
                history = []

        records: List[ApproverRecord] = []
        for h in history:
            if isinstance(h, dict):
                records.append(
                    ApproverRecord(
                        approver_id=str(h.get("approver_id", "")),
                        role=h.get("role"),
                        action=str(h.get("action", "")),
                        dwell_seconds=int(h.get("dwell_seconds", 0)),
                        signer_type=h.get("signer_type"),
                        signature_hex=h.get("signature_hex"),
                        comment=h.get("comment"),
                        timestamp=h.get("timestamp"),
                    )
                )
        return records
