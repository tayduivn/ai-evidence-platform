"""Background daemon worker delivering micro-batches with persistent HTTP connections."""

import http.client
import json
import logging
import random
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.models import ClientConfig

logger = logging.getLogger("ai_evidence_sdk.worker")


class DeliveryWorker:
    """
    Dedicated daemon thread responsible for draining events from BoundedEventQueue
    and delivering them to the Gateway Ingest API over a persistent HTTP keep-alive connection.
    Implements micro-batching, full jitter exponential backoff, and graceful draining.
    """

    def __init__(
        self,
        buffer: BoundedEventQueue,
        config: ClientConfig,
    ):
        self._buffer = buffer
        self._config = config

        parsed = urllib.parse.urlparse(config.ingest_url)
        self._scheme = parsed.scheme or "http"
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self._path = parsed.path or "/api/v1/ml/ingest"

        self._conn: Optional[http.client.HTTPConnection] = None
        self._is_running = True
        self._stop_requested = threading.Event()
        self._wake_event = threading.Event()
        self._idle_event = threading.Event()
        self._idle_event.set()

        self._consecutive_failures = 0
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="ai-evidence-delivery-worker",
        )
        self._thread.start()

    def notify_new_item(self) -> None:
        """Wakes up the delivery worker immediately when a new event arrives."""
        self._wake_event.set()

    def _get_connection(self) -> http.client.HTTPConnection:
        if self._conn is not None:
            return self._conn

        timeout = self._config.http_timeout_sec
        if self._scheme == "https":
            self._conn = http.client.HTTPSConnection(self._host, self._port, timeout=timeout)
        else:
            self._conn = http.client.HTTPConnection(self._host, self._port, timeout=timeout)
        return self._conn

    def _close_connection(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _run_loop(self) -> None:
        while self._is_running:
            # Drain batch
            batch = self._buffer.drain_batch(self._config.batch_size)

            if not batch:
                self._idle_event.set()
                if self._stop_requested.is_set():
                    break
                # Wait for new events or timeout
                self._wake_event.wait(timeout=self._config.flush_interval_sec)
                self._wake_event.clear()
                continue

            self._idle_event.clear()
            self._deliver_batch(batch)

        self._idle_event.set()
        self._close_connection()

    def _deliver_batch(self, batch: List[Dict[str, Any]]) -> None:
        for event in batch:
            if not self._is_running and not self._stop_requested.is_set():
                break
            self._deliver_single_event(event)

    def _deliver_single_event(self, event: Dict[str, Any]) -> None:
        try:
            payload_bytes = json.dumps(event, default=str).encode("utf-8")
        except Exception as ex:
            logger.warning("Event serialization failed, dropping item: %s", ex)
            return

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ai-evidence-sdk-python/0.3.0",
        }
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        if "ai_system_id" in event:
            headers["X-AI-System-ID"] = str(event["ai_system_id"])
        if "correlation_id" in event and event["correlation_id"]:
            headers["X-Correlation-ID"] = str(event["correlation_id"])

        max_retries = self._config.max_retries
        attempts = 0

        while attempts <= max_retries and self._is_running:
            attempts += 1
            try:
                conn = self._get_connection()
                conn.request("POST", self._path, body=payload_bytes, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                resp.read()  # Consume body to allow connection reuse

                if status in (200, 201, 202):
                    self._consecutive_failures = 0
                    return
                elif status in (400, 403):
                    # Fatal client error (e.g. malformed or Shadow AI forbidden)
                    logger.warning(
                        "Server rejected event with fatal status %d: dropping item to prevent poison pill",
                        status,
                    )
                    self._consecutive_failures = 0
                    return
                else:
                    # Transient server error (500, 502, 503, 504, 429)
                    self._consecutive_failures += 1
                    self._close_connection()

            except Exception as ex:
                self._consecutive_failures += 1
                self._close_connection()
                logger.debug("Network transmission attempt %d failed: %s", attempts, ex)

            # Full jitter backoff on transient failure
            if attempts <= max_retries and self._is_running:
                backoff_cap = min(
                    self._config.max_backoff_sec,
                    self._config.base_backoff_sec * (2 ** min(self._consecutive_failures, 8)),
                )
                sleep_duration = random.uniform(0, backoff_cap)
                self._stop_requested.wait(timeout=sleep_duration)

    def flush(self, timeout: Optional[float] = 5.0) -> bool:
        """
        Blocks until all currently queued events are drained and delivered,
        or until the timeout expires.
        """
        start_time = time.monotonic()
        self._wake_event.set()

        while time.monotonic() - start_time < (timeout or 5.0):
            if len(self._buffer) == 0 and self._idle_event.is_set():
                return True
            time.sleep(0.01)

        return len(self._buffer) == 0

    def stop(self, timeout: Optional[float] = 5.0) -> None:
        """
        Signals the worker to drain remaining events and stop execution cleanly.
        """
        self._stop_requested.set()
        self._wake_event.set()
        self.flush(timeout=timeout)
        self._is_running = False
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._close_connection()
