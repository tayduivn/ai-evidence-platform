"""Unit tests for DeliveryWorker background thread and HTTP transport."""

import time
import pytest

from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.models import ClientConfig, DropPolicy
from ai_evidence_sdk.worker import DeliveryWorker


def test_delivery_worker_successful_drain(mock_gateway):
    buffer = BoundedEventQueue(max_size=100, drop_policy=DropPolicy.DROP_OLDEST)
    config = ClientConfig(
        ingest_url=mock_gateway.ingest_url,
        batch_size=10,
        flush_interval_sec=0.02,
        http_timeout_sec=1.0,
    )

    worker = DeliveryWorker(buffer=buffer, config=config)

    try:
        # Enqueue 5 events
        for i in range(5):
            buffer.enqueue({"ai_system_id": "test-model", "score": 0.8, "i": i})
        worker.notify_new_item()

        # Flush
        flushed = worker.flush(timeout=2.0)
        assert flushed is True
        assert len(buffer) == 0
        assert len(mock_gateway.received_posts) == 5
    finally:
        worker.stop(timeout=1.0)


def test_delivery_worker_fatal_400_drop(mock_gateway):
    mock_gateway.injected_status = 400
    buffer = BoundedEventQueue(max_size=10, drop_policy=DropPolicy.DROP_OLDEST)
    config = ClientConfig(
        ingest_url=mock_gateway.ingest_url,
        batch_size=5,
        flush_interval_sec=0.02,
        max_retries=2,
    )

    worker = DeliveryWorker(buffer=buffer, config=config)

    try:
        buffer.enqueue({"ai_system_id": "bad-payload", "score": None})
        worker.notify_new_item()

        # Fatal 400 error should cause worker to drop item immediately without retrying
        worker.flush(timeout=1.0)
        assert len(buffer) == 0
        assert len(mock_gateway.received_posts) == 1
    finally:
        worker.stop(timeout=1.0)


def test_delivery_worker_transient_500_retry(mock_gateway):
    mock_gateway.injected_status = 500
    buffer = BoundedEventQueue(max_size=10, drop_policy=DropPolicy.DROP_OLDEST)
    config = ClientConfig(
        ingest_url=mock_gateway.ingest_url,
        batch_size=5,
        flush_interval_sec=0.01,
        base_backoff_sec=0.01,
        max_retries=2,
    )

    worker = DeliveryWorker(buffer=buffer, config=config)

    try:
        buffer.enqueue({"ai_system_id": "transient-model", "score": 0.5})
        worker.notify_new_item()
        time.sleep(0.15)

        # Multiple attempts should have occurred due to retries
        assert len(mock_gateway.received_posts) >= 2
    finally:
        worker.stop(timeout=1.0)
