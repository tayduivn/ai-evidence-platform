"""
Gateway Latency Overhead Benchmark.

Empirically measures p50, p90, p95, and p99 latency overhead of Go Gateway reverse proxy
vs direct upstream Mock LLM across 100+ requests with 50KB payload.
Strictly asserts that p95 latency overhead is < 15.0ms.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.mock_llm.server import MockLLMServer


def find_free_port() -> int:
    """Finds an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def compute_percentiles(latencies: List[float]) -> Dict[str, float]:
    """Computes distribution statistics (min, p50, p90, p95, p99, max, mean)."""
    sorted_lats = sorted(latencies)
    n = len(sorted_lats)
    if n == 0:
        return {}
    return {
        "count": n,
        "min_ms": round(sorted_lats[0], 3),
        "p50_ms": round(sorted_lats[int(n * 0.50)], 3),
        "p90_ms": round(sorted_lats[int(n * 0.90)], 3),
        "p95_ms": round(sorted_lats[int(n * 0.95)], 3),
        "p99_ms": round(sorted_lats[int(n * 0.99)], 3),
        "max_ms": round(sorted_lats[-1], 3),
        "mean_ms": round(sum(sorted_lats) / n, 3),
    }


def execute_http_request(
    url: str,
    headers: Dict[str, str],
    payload_bytes: bytes,
    session: Optional[requests.Session] = None
) -> Tuple[float, int, bytes]:
    """Executes a single HTTP POST request and returns elapsed time in milliseconds."""
    start = time.perf_counter()
    if session is not None:
        try:
            resp = session.post(url, data=payload_bytes, headers=headers, timeout=30.0)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return elapsed_ms, resp.status_code, resp.content
        except requests.RequestException as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            status_code = getattr(e.response, "status_code", 500) if getattr(e, "response", None) else 500
            content = getattr(e.response, "content", b"") if getattr(e, "response", None) else str(e).encode()
            return elapsed_ms, status_code, content
    else:
        req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                body = resp.read()
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return elapsed_ms, resp.status, body
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return elapsed_ms, e.code, e.read()


def wait_for_health(url: str, timeout: float = 10.0, session: Optional[requests.Session] = None) -> bool:
    """Polls a health endpoint until 200 OK or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            if session is not None:
                resp = session.get(url, timeout=1.0)
                if resp.status_code == 200:
                    return True
            else:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        return True
        except Exception:
            time.sleep(0.1)
    return False


def run_benchmark(
    num_requests: int = 150,
    warmup_requests: int = 20,
    strict_assert: bool = True
) -> Dict[str, any]:
    """Executes the Gateway vs Direct Mock LLM benchmark suite."""
    print("=" * 78)
    print("AI GATEWAY LATENCY OVERHEAD EMPIRICAL BENCHMARK (50KB PAYLOAD)")
    print("=" * 78)

    # 1. Load 50KB payload
    payload_file = PROJECT_ROOT / "tests" / "fixtures" / "payloads" / "payload_50kb.json"
    if not payload_file.exists():
        raise FileNotFoundError(f"Fixture not found: {payload_file}")
    payload_bytes = payload_file.read_bytes()
    payload_kb = len(payload_bytes) / 1024.0
    print(f"[*] Loaded Benchmark Payload: {payload_file.name} ({payload_kb:.2f} KB, {len(payload_bytes)} bytes)")

    # 2. Start Mock LLM Server
    mock_llm = MockLLMServer(host="127.0.0.1", port=0)
    mock_port = mock_llm.start()
    mock_url = f"http://127.0.0.1:{mock_port}/v1/chat/completions"
    print(f"[+] Mock LLM Server listening at: http://127.0.0.1:{mock_port}")

    # 3. Ensure Gateway binary is compiled
    gw_bin = PROJECT_ROOT / "services" / "gateway" / "gateway.exe"
    if not gw_bin.exists():
        print("[*] Compiling Go Gateway binary...")
        cmd = ["C:\\Program Files\\Go\\bin\\go.exe", "build", "-o", "gateway.exe", "./cmd/gateway"]
        res = subprocess.run(cmd, cwd=str(PROJECT_ROOT / "services" / "gateway"), capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Go Gateway build failed: {res.stderr}")

    gw_port = find_free_port()
    gw_url = f"http://127.0.0.1:{gw_port}/v1/chat/completions"
    gw_health = f"http://127.0.0.1:{gw_port}/health"

    env = os.environ.copy()
    env["GATEWAY_PORT"] = str(gw_port)
    env["UPSTREAM_LLM_URL"] = f"http://127.0.0.1:{mock_port}"
    env["LEDGER_QUEUE_CAPACITY"] = "50000"

    print(f"[*] Starting Go Gateway on port {gw_port} (upstream -> {mock_port})...")
    gw_proc = subprocess.Popen(
        [str(gw_bin)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(PROJECT_ROOT)
    )

    # Initialize connection pooling session matching test_tier5_adversarial.py
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        if not wait_for_health(gw_health, timeout=10.0, session=session):
            raise TimeoutError(f"Gateway failed to become healthy at {gw_health}")
        print(f"[+] Go Gateway healthy and ready at: {gw_url}")

        direct_headers = {
            "Content-Type": "application/json",
            "X-Correlation-ID": "bench-direct",
        }
        gw_headers = {
            "Content-Type": "application/json",
            "X-AI-System-ID": "securities-quant-advisor-v1",
            "X-Correlation-ID": "bench-gw",
        }

        # 4. Warm-up Phase
        print(f"[*] Executing {warmup_requests} warm-up requests per target...")
        for _ in range(warmup_requests):
            execute_http_request(mock_url, direct_headers, payload_bytes, session=session)
            execute_http_request(gw_url, gw_headers, payload_bytes, session=session)
        print("[+] Warm-up phase complete.")

        # 5. Measure Direct Mock LLM
        print(f"[*] Benchmarking Direct Upstream Mock LLM ({num_requests} requests)...")
        direct_latencies: List[float] = []
        for i in range(num_requests):
            elapsed_ms, status, _ = execute_http_request(mock_url, direct_headers, payload_bytes, session=session)
            assert status == 200, f"Direct request {i} failed with status {status}"
            direct_latencies.append(elapsed_ms)

        # 6. Measure Proxied Gateway
        print(f"[*] Benchmarking Go Gateway Reverse Proxy ({num_requests} requests)...")
        gw_latencies: List[float] = []
        for i in range(num_requests):
            elapsed_ms, status, _ = execute_http_request(gw_url, gw_headers, payload_bytes, session=session)
            assert status == 200, f"Gateway request {i} failed with status {status}"
            gw_latencies.append(elapsed_ms)

        # 7. Compute Distributions
        direct_metrics = compute_percentiles(direct_latencies)
        gw_metrics = compute_percentiles(gw_latencies)

        # Compute paired overhead (request-by-request diff) and aggregate percentile delta
        paired_overheads = [max(0.0, gw_latencies[i] - direct_latencies[i]) for i in range(num_requests)]
        paired_metrics = compute_percentiles(paired_overheads)

        overhead_p50 = round(gw_metrics["p50_ms"] - direct_metrics["p50_ms"], 3)
        overhead_p90 = round(gw_metrics["p90_ms"] - direct_metrics["p90_ms"], 3)
        overhead_p95 = round(gw_metrics["p95_ms"] - direct_metrics["p95_ms"], 3)
        overhead_p99 = round(gw_metrics["p99_ms"] - direct_metrics["p99_ms"], 3)

        print("\n" + "=" * 78)
        print("EMPIRICAL LATENCY BENCHMARK RESULTS")
        print("=" * 78)
        print(f"{'Metric':<12} | {'Direct (ms)':<15} | {'Gateway (ms)':<15} | {'Delta Overhead':<15} | {'Paired Overhead'}")
        print("-" * 78)
        print(f"{'Min':<12} | {direct_metrics['min_ms']:<15.3f} | {gw_metrics['min_ms']:<15.3f} | {gw_metrics['min_ms'] - direct_metrics['min_ms']:<15.3f} | {paired_metrics['min_ms']:.3f} ms")
        print(f"{'p50':<12} | {direct_metrics['p50_ms']:<15.3f} | {gw_metrics['p50_ms']:<15.3f} | {overhead_p50:<15.3f} | {paired_metrics['p50_ms']:.3f} ms")
        print(f"{'p90':<12} | {direct_metrics['p90_ms']:<15.3f} | {gw_metrics['p90_ms']:<15.3f} | {overhead_p90:<15.3f} | {paired_metrics['p90_ms']:.3f} ms")
        print(f"{'p95':<12} | {direct_metrics['p95_ms']:<15.3f} | {gw_metrics['p95_ms']:<15.3f} | {overhead_p95:<15.3f} | {paired_metrics['p95_ms']:.3f} ms")
        print(f"{'p99':<12} | {direct_metrics['p99_ms']:<15.3f} | {gw_metrics['p99_ms']:<15.3f} | {overhead_p99:<15.3f} | {paired_metrics['p99_ms']:.3f} ms")
        print(f"{'Max':<12} | {direct_metrics['max_ms']:<15.3f} | {gw_metrics['max_ms']:<15.3f} | {gw_metrics['max_ms'] - direct_metrics['max_ms']:<15.3f} | {paired_metrics['max_ms']:.3f} ms")
        print(f"{'Mean':<12} | {direct_metrics['mean_ms']:<15.3f} | {gw_metrics['mean_ms']:<15.3f} | {gw_metrics['mean_ms'] - direct_metrics['mean_ms']:<15.3f} | {paired_metrics['mean_ms']:.3f} ms")
        print("=" * 78)

        # 8. SLA Validation
        effective_p95_overhead = overhead_p95
        print(f"\n[*] SLA Contract Assertion: p95 Overhead < 15.0ms (Measured: {effective_p95_overhead:.3f}ms)")
        if strict_assert:
            assert effective_p95_overhead < 15.0, (
                f"SLA VIOLATION: Gateway p95 overhead of {effective_p95_overhead:.3f}ms >= 15.0ms limit"
            )
            print("[+] >>> BENCHMARK PASSED: Strictly verified p95 overhead < 15.0ms <<<")

        result = {
            "payload_size_kb": payload_kb,
            "requests_count": num_requests,
            "direct": direct_metrics,
            "gateway": gw_metrics,
            "overhead_percentiles": {
                "p50_ms": overhead_p50,
                "p90_ms": overhead_p90,
                "p95_ms": overhead_p95,
                "p99_ms": overhead_p99,
            },
            "paired_overhead": paired_metrics,
            "sla_target_ms": 15.0,
            "sla_passed": bool(effective_p95_overhead < 15.0)
        }

        # Save result JSON
        results_file = PROJECT_ROOT / "tests" / "benchmarks" / "gateway_overhead_results.json"
        results_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[+] Detailed benchmark metrics written to: {results_file}")

        return result

    finally:
        # Graceful cleanup
        session.close()
        if gw_proc.poll() is None:
            gw_proc.terminate()
            try:
                gw_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                gw_proc.kill()
        mock_llm.stop()
        print("[+] Mock LLM & Gateway stopped cleanly.")


if __name__ == "__main__":
    run_benchmark(num_requests=120, warmup_requests=20, strict_assert=True)
