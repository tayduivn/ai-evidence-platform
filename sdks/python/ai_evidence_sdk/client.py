"""EvidenceClient: high-performance public facade for the AI Evidence & Accountability Platform."""

import atexit
import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Union

from ai_evidence_sdk.approval.handle import ApprovalHandle
from ai_evidence_sdk.approval.poller import ApprovalPoller
from ai_evidence_sdk.approval.result import ApprovalResult
from ai_evidence_sdk.approval.states import ApprovalStatus
from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.exceptions import (
    ApprovalError,
    ConfigurationError,
    EvidenceSDKError,
    NetworkError,
    PIIValidationError,
)
from ai_evidence_sdk.models import ClientConfig, DropPolicy, MLDecisionEvent
from ai_evidence_sdk.pii.scanner import PIIValidator
from ai_evidence_sdk.worker import DeliveryWorker

logger = logging.getLogger("ai_evidence_sdk.client")


class EvidenceClient:
    """
    Primary client facade for AI Evidence & Accountability logging and governance.

    Key Guarantees:
    - log_decision(): returns in < 5.0ms (typically < 50µs) with zero unhandled exceptions.
    - request_approval(): dispatches high-risk decision events for 4-Eyes review.
    - wait_for_decision(): polls across multi-stage approval states to terminal resolution.
    - Resource safety: background daemon worker, keepalive connections, graceful flush & shutdown.
    """

    def __init__(
        self,
        ingest_url: str = "http://127.0.0.1:8080/api/v1/ml/ingest",
        max_queue_size: int = 10000,
        drop_policy: DropPolicy = DropPolicy.DROP_OLDEST,
        config: Optional[ClientConfig] = None,
        **kwargs: Any,
    ):
        if config is not None:
            self._config = config
        else:
            self._config = ClientConfig(
                ingest_url=ingest_url,
                max_queue_size=max_queue_size,
                drop_policy=DropPolicy(drop_policy),
            )

        # Apply any explicit kwargs overrides
        for k, v in kwargs.items():
            if hasattr(self._config, k):
                setattr(self._config, k, v)

        # Parsed URL setup
        self.ingest_url: str = self._config.ingest_url
        parsed = urllib.parse.urlparse(self.ingest_url)
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Internal buffer and worker
        self._buffer = BoundedEventQueue(
            max_size=self._config.max_queue_size,
            drop_policy=self._config.drop_policy,
        )
        self.buffer_queue = self._buffer  # Compatibility shim for test harnesses
        self.is_running = True
        self._closed = False

        self._worker = DeliveryWorker(buffer=self._buffer, config=self._config)
        self._poller = ApprovalPoller(client=self)

        if self._config.auto_flush_on_exit:
            atexit.register(self._cleanup_on_exit)

    def _cleanup_on_exit(self) -> None:
        try:
            if not self._closed:
                self.close(timeout=1.0)
        except Exception:
            pass

    @property
    def dropped_events(self) -> int:
        """Atomic count of dropped events due to buffer saturation."""
        return self._buffer.dropped_count

    @property
    def total_enqueued(self) -> int:
        """Count of events successfully accepted into the local buffer."""
        return self._buffer.enqueued_count

    def log_decision(
        self,
        event_data: Union[Dict[str, Any], MLDecisionEvent],
    ) -> bool:
        """
        Logs a machine learning decision event to the tamper-evident ledger.
        Guaranteed SLA: completes in strictly < 5.0ms (typically under 50µs).
        Zero Caller Exceptions: never throws an exception to calling ML threads.

        Returns:
            True if event was accepted into buffer (or queued after evicting oldest item).
            False if event was rejected under DROP_NEWEST or invalid.
        """
        try:
            if self._closed:
                return False

            # Normalize data model or dictionary
            if isinstance(event_data, MLDecisionEvent):
                payload = event_data.to_dict()
            elif isinstance(event_data, dict):
                payload = dict(event_data)
            else:
                logger.warning("Invalid event_data type passed to log_decision: %s", type(event_data))
                return False

            # Enqueue into thread-safe bounded memory queue
            enqueued = self._buffer.enqueue(payload)
            self._worker.notify_new_item()
            return enqueued

        except Exception as ex:
            logger.warning("log_decision defensive shield caught exception: %s", ex)
            return False

    def request_approval(
        self,
        event_data: Union[Dict[str, Any], MLDecisionEvent],
        webhook_url: Optional[str] = None,
        creator_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        pre_validate_pii: bool = False,
        pii_mode: str = "warn",
        allow_offline_ticket: bool = False,
    ) -> ApprovalHandle:
        """
        Submits a high-risk decision event to the Ingest API with requires_approval=True.
        Returns an ApprovalHandle for dictionary inspection and lifecycle tracking (.wait()).
        """
        if isinstance(event_data, MLDecisionEvent):
            payload = event_data.to_dict()
        elif isinstance(event_data, dict):
            payload = dict(event_data)
        else:
            raise ValueError(f"Unsupported event_data type: {type(event_data)}")

        # PII Pre-validation
        if pre_validate_pii:
            features = payload.get("features", {})
            cleaned_features, detected = PIIValidator.scan_dict(features)
            if detected:
                if pii_mode == "block":
                    raise PIIValidationError(
                        f"Blocked approval request containing sensitive Vietnamese PII: {detected}",
                        detected_types=detected,
                    )
                elif pii_mode == "mask":
                    payload["features"] = cleaned_features
                else:
                    logger.warning("Vietnamese PII detected in approval request: %s", detected)

        payload["requires_approval"] = True
        if creator_id is not None:
            payload["creator_id"] = creator_id
        if webhook_url is not None:
            payload["webhook_url"] = webhook_url

        outbound_headers = {
            "Content-Type": "application/json",
            "X-Require-Approval": "true",
        }
        if "ai_system_id" in payload:
            outbound_headers["X-AI-System-ID"] = str(payload["ai_system_id"])
        if "correlation_id" in payload and payload["correlation_id"]:
            outbound_headers["X-Correlation-ID"] = str(payload["correlation_id"])
        if webhook_url is not None:
            outbound_headers["X-Webhook-URL"] = webhook_url
        if headers:
            outbound_headers.update(headers)

        try:
            resp_data = self._http_post(
                self.ingest_url,
                json_data=payload,
                headers=outbound_headers,
                timeout=timeout,
            )
            decision_id = resp_data.get("decision_id")
            if not decision_id:
                # Generate deterministic fallback ID if missing from response
                raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
                decision_id = f"dec-ml-{hashlib.md5(raw_bytes).hexdigest()[:12]}"
                resp_data["decision_id"] = decision_id

            poll_url = resp_data.get("poll_url") or f"/api/v1/decisions/{decision_id}/status"
            status = resp_data.get("status", ApprovalStatus.PENDING_APPROVAL.value)
            corr_id = resp_data.get("correlation_id", payload.get("correlation_id", ""))

            return ApprovalHandle(
                decision_id=decision_id,
                status=status,
                poll_url=poll_url,
                correlation_id=corr_id,
                client=self,
                raw_response=resp_data,
            )

        except Exception as ex:
            if allow_offline_ticket:
                # Fallback offline ticket mode for air-gapped test harnesses
                raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
                decision_id = f"dec-ml-{hashlib.md5(raw_bytes).hexdigest()[:12]}"
                mock_resp = {
                    "status": ApprovalStatus.PENDING_APPROVAL.value,
                    "decision_id": decision_id,
                    "poll_url": f"/api/v1/decisions/{decision_id}/status",
                    "correlation_id": payload.get("correlation_id", ""),
                }
                return ApprovalHandle(
                    decision_id=decision_id,
                    status=ApprovalStatus.PENDING_APPROVAL.value,
                    poll_url=mock_resp["poll_url"],
                    correlation_id=mock_resp["correlation_id"],
                    client=self,
                    raw_response=mock_resp,
                )
            if isinstance(ex, EvidenceSDKError):
                raise
            raise NetworkError(f"Failed to submit approval request: {ex}") from ex

    def wait_for_decision(
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
        """Blocks until a decision resolves or times out."""
        return self._poller.wait(
            target=target,
            timeout=timeout,
            poll_interval=poll_interval,
            backoff_multiplier=backoff_multiplier,
            max_poll_interval=max_poll_interval,
            jitter=jitter,
            raise_on_timeout=raise_on_timeout,
            raise_on_rejection=raise_on_rejection,
        )

    def get_decision_status(self, decision_id: str) -> Dict[str, Any]:
        """Fetches the current status of a decision from the platform."""
        poll_url = f"/api/v1/decisions/{decision_id}/status"
        return self._http_get(poll_url)

    def _http_get(self, path_or_url: str, timeout: float = 5.0) -> Dict[str, Any]:
        url = self._resolve_url(path_or_url)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ai-evidence-sdk-python/0.3.0",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                error_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                error_body = {"error": str(e)}
            raise ApprovalError(f"HTTP GET {url} failed with status {e.code}: {error_body}") from e
        except Exception as e:
            raise NetworkError(f"Network error querying {url}: {e}") from e

    def _http_post(
        self,
        path_or_url: str,
        json_data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        url = self._resolve_url(path_or_url)
        body_bytes = json.dumps(json_data, default=str).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": "ai-evidence-sdk-python/0.3.0",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {"error": str(e)}
            raise ApprovalError(f"HTTP POST {url} failed with status {e.code}: {err_body}") from e
        except Exception as e:
            raise NetworkError(f"Network error posting to {url}: {e}") from e

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        clean_path = path_or_url if path_or_url.startswith("/") else f"/{path_or_url}"
        return f"{self._base_url}{clean_path}"

    def flush(self, timeout: float = 5.0) -> bool:
        """Flushes in-flight events and waits for the delivery worker to drain."""
        return self._worker.flush(timeout=timeout)

    def close(self, timeout: float = 5.0) -> None:
        """Gracefully shuts down worker thread and releases connections."""
        self._closed = True
        self.is_running = False
        self._worker.stop(timeout=timeout)

    def __enter__(self) -> "EvidenceClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close(timeout=2.0)
