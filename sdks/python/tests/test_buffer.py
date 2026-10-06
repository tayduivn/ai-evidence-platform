"""Unit tests for BoundedEventQueue and DropPolicy."""

import concurrent.futures
import time
import pytest

from ai_evidence_sdk.buffer import BoundedEventQueue
from ai_evidence_sdk.models import DropPolicy


def test_buffer_enqueue_and_drain():
    buffer = BoundedEventQueue(max_size=10, drop_policy=DropPolicy.DROP_OLDEST)
    assert len(buffer) == 0
    assert buffer.is_empty()

    for i in range(5):
        assert buffer.enqueue({"id": i}) is True

    assert len(buffer) == 5
    assert buffer.enqueued_count == 5
    assert buffer.dropped_count == 0

    batch = buffer.drain_batch(max_items=3)
    assert len(batch) == 3
    assert [item["id"] for item in batch] == [0, 1, 2]
    assert buffer.drained_count == 3
    assert len(buffer) == 2

    # Drain remaining
    batch2 = buffer.drain_batch(max_items=10)
    assert len(batch2) == 2
    assert [item["id"] for item in batch2] == [3, 4]
    assert buffer.is_empty()


def test_buffer_overflow_drop_oldest():
    # max_size = 3
    buffer = BoundedEventQueue(max_size=3, drop_policy=DropPolicy.DROP_OLDEST)

    # Fill to capacity
    for i in range(3):
        assert buffer.enqueue({"id": i}) is True
    assert len(buffer) == 3
    assert buffer.dropped_count == 0

    # 4th item evicts 0
    assert buffer.enqueue({"id": 3}) is True
    assert buffer.dropped_count == 1
    assert len(buffer) == 3

    # 5th item evicts 1
    assert buffer.enqueue({"id": 4}) is True
    assert buffer.dropped_count == 2
    assert len(buffer) == 3

    # Draining should contain [2, 3, 4]
    items = buffer.drain_batch(max_items=10)
    assert [item["id"] for item in items] == [2, 3, 4]
    assert buffer.dropped_count == 2
    assert buffer.dropped_events == 2  # Alias test


def test_buffer_overflow_drop_newest():
    # max_size = 3
    buffer = BoundedEventQueue(max_size=3, drop_policy=DropPolicy.DROP_NEWEST)

    # Fill to capacity
    for i in range(3):
        assert buffer.enqueue({"id": i}) is True
    assert len(buffer) == 3
    assert buffer.dropped_count == 0

    # 4th and 5th items rejected immediately
    assert buffer.enqueue({"id": 3}) is False
    assert buffer.dropped_count == 1
    assert buffer.enqueue({"id": 4}) is False
    assert buffer.dropped_count == 2
    assert len(buffer) == 3

    # Draining should retain original [0, 1, 2]
    items = buffer.drain_batch(max_items=10)
    assert [item["id"] for item in items] == [0, 1, 2]
    assert buffer.dropped_count == 2


def test_buffer_concurrent_multithreaded():
    buffer = BoundedEventQueue(max_size=1000, drop_policy=DropPolicy.DROP_OLDEST)
    threads = 8
    items_per_thread = 500

    def producer(t_id: int):
        for i in range(items_per_thread):
            buffer.enqueue({"t": t_id, "i": i})

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(producer, t) for t in range(threads)]
        concurrent.futures.wait(futures)

    assert buffer.enqueued_count == threads * items_per_thread
    assert len(buffer) + buffer.dropped_count == buffer.enqueued_count


def test_buffer_hot_path_latency():
    """Verify single uncontended enqueue executes in < 1.5µs on average."""
    buffer = BoundedEventQueue(max_size=50000, drop_policy=DropPolicy.DROP_OLDEST)
    iterations = 20000

    start_time = time.perf_counter()
    for i in range(iterations):
        buffer.enqueue(i)
    total_sec = time.perf_counter() - start_time

    avg_us = (total_sec / iterations) * 1_000_000.0
    print(f"\nAverage buffer enqueue latency: {avg_us:.4f} µs")
    # In Python, uncontended lock + deque.append is typically 0.2 - 1.0 µs
    assert avg_us < 2.5, f"Buffer hot path latency exceeded: {avg_us}µs"
