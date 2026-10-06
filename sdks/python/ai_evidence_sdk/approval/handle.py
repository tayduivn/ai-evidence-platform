"""ApprovalHandle implementing Mapping ABC for dual dictionary and object access."""

import collections.abc
from typing import Any, Dict, Iterator, Optional


class ApprovalHandle(collections.abc.Mapping):
    """
    Tracking handle returned by EvidenceClient.request_approval().
    Fully satisfies test assertions expecting dict-like subscripting:
        assert res["status"] == "PENDING_APPROVAL"
        assert "decision_id" in res
        assert "poll_url" in res
    while exposing object attributes and .wait() / .poll() workflow methods.
    """

    def __init__(
        self,
        decision_id: str,
        status: str,
        poll_url: str,
        correlation_id: str = "",
        client: Optional[Any] = None,
        raw_response: Optional[Dict[str, Any]] = None,
    ):
        self._decision_id = str(decision_id)
        self._status = str(status)
        self._poll_url = str(poll_url)
        self._correlation_id = str(correlation_id)
        self._client = client
        self._raw = raw_response or {
            "status": self._status,
            "decision_id": self._decision_id,
            "poll_url": self._poll_url,
            "correlation_id": self._correlation_id,
        }

    # Mapping ABC implementation
    def __getitem__(self, key: str) -> Any:
        return self._raw[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)

    def __contains__(self, key: object) -> bool:
        return key in self._raw

    def get(self, key: str, default: Any = None) -> Any:
        return self._raw.get(key, default)

    # Properties
    @property
    def decision_id(self) -> str:
        return self._decision_id

    @property
    def status(self) -> str:
        return self._status

    @property
    def poll_url(self) -> str:
        return self._poll_url

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    # Polling ergonomics
    def wait(
        self,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        backoff_multiplier: float = 1.2,
        max_poll_interval: float = 5.0,
        jitter: bool = True,
        raise_on_timeout: bool = True,
        raise_on_rejection: bool = False,
    ) -> Any:
        """Blocks and polls until the decision reaches a terminal state or times out."""
        if self._client is None:
            raise RuntimeError("Cannot wait on ApprovalHandle without an associated EvidenceClient")
        return self._client.wait_for_decision(
            self,
            timeout=timeout,
            poll_interval=poll_interval,
            backoff_multiplier=backoff_multiplier,
            max_poll_interval=max_poll_interval,
            jitter=jitter,
            raise_on_timeout=raise_on_timeout,
            raise_on_rejection=raise_on_rejection,
        )

    def poll(self) -> str:
        """Performs a single poll request and updates internal status."""
        if self._client is None:
            raise RuntimeError("Cannot poll ApprovalHandle without an associated EvidenceClient")
        latest = self._client.get_decision_status(self._decision_id)
        new_status = latest.get("status", self._status)
        self._status = new_status
        self._raw["status"] = new_status
        return self._status

    def to_dict(self) -> Dict[str, Any]:
        """Returns a copy of the underlying response dictionary."""
        return dict(self._raw)

    def __repr__(self) -> str:
        return (
            f"<ApprovalHandle decision_id='{self._decision_id}' "
            f"status='{self._status}' poll_url='{self._poll_url}'>"
        )
