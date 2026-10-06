"""Performance benchmark tests verifying the strict < 5.0ms non-blocking SLA."""

import concurrent.futures
import time
import pytest

from ai_evidence_sdk.client import EvidenceClient


def test_benchmark_sequential_log_decision_strict_sla(mock_gateway):
    """
    Benchmark asserting that 1,000 sequential log_decision calls
    strictly satisfy the < 5.0ms SLA guarantee.
    """
    client = EvidenceClient(
        ingest_url=mock_gateway.ingest_url,
        max_queue_size=2000,
    )

    latencies_ms = []
    iterations = 1000

    try:
        for i in range(iterations):
            payload = {
                "ai_system_id": "benchmark-model-v1",
                "score": 0.88,
                "features": {"f1": i, "f2": 100.5, "tag": "benchmark_run"},
            }
            t0 = time.perf_counter()
            success = client.log_decision(payload)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            latencies_ms.append(elapsed_ms)
            assert success is True
            assert elapsed_ms < 5.0, f"SLA violation at iteration {i}: {elapsed_ms:.4f}ms"

        sorted_lat = sorted(latencies_ms)
        max_lat = max(latencies_ms)
        p99_lat = sorted_lat[int(len(latencies_ms) * 0.99)]
        p95_lat = sorted_lat[int(len(latencies_ms) * 0.95)]
        p50_lat = sorted_lat[int(len(latencies_ms) * 0.50)]
        mean_lat = sum(latencies_ms) / len(latencies_ms)

        print(
            f"\n[BENCHMARK SLA RESULTS] Iterations: {iterations} | "
            f"Max: {max_lat:.4f}ms | P99: {p99_lat:.4f}ms | P95: {p95_lat:.4f}ms | "
            f"P50: {p50_lat:.4f}ms | Mean: {mean_lat:.4f}ms"
        )

        assert max_lat < 5.0, f"Max latency violated 5.0ms SLA: {max_lat:.4f}ms"
        assert p99_lat < 0.25, f"P99 latency too high: {p99_lat:.4f}ms"
    finally:
        client.close(timeout=1.0)


def test_benchmark_multithreaded_concurrent_sla(mock_gateway):
    """
    Benchmark asserting that 8 concurrent threads executing 250 calls each (2,000 total)
    all strictly complete within < 5.0ms per call.
    """
    client = EvidenceClient(
        ingest_url=mock_gateway.ingest_url,
        max_queue_size=5000,
    )

    num_threads = 8
    calls_per_thread = 250
    all_latencies_ms = []

    def run_worker(thread_id: int):
        thread_latencies = []
        for i in range(calls_per_thread):
            t0 = time.perf_counter()
            success = client.log_decision(
                {"ai_system_id": "mt-model", "score": 0.9, "t": thread_id, "i": i}
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            thread_latencies.append(elapsed_ms)
            assert success is True
            assert elapsed_ms < 5.0
        return thread_latencies

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(run_worker, tid) for tid in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                all_latencies_ms.extend(f.result())

        assert len(all_latencies_ms) == num_threads * calls_per_thread
        max_lat = max(all_latencies_ms)
        p99_lat = sorted(all_latencies_ms)[int(len(all_latencies_ms) * 0.99)]

        print(
            f"\n[CONCURRENT BENCHMARK RESULTS] Total calls: {len(all_latencies_ms)} | "
            f"Max: {max_lat:.4f}ms | P99: {p99_lat:.4f}ms"
        )
        assert max_lat < 5.0
    finally:
        client.close(timeout=1.0)
