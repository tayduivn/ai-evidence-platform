"""
Standalone E2E Test Suite Runner for AI Evidence & Accountability Platform.
Supports:
- Running specific tiers: python tests/e2e/run_tests.py --tier 1 (or 2, 3, 4)
- Running all tiers: python tests/e2e/run_tests.py --all
- Self-contained execution with automatic mock LLM orchestration and fixture generation
- Exit code 0 on 100% pass
"""

import argparse
import os
import sys
import time
from pathlib import Path

# Ensure root directory is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.mock_llm.server import MockLLMServer


def ensure_fixtures():
    """Ensure test fixtures (certs, payloads, evidence packs) are generated."""
    fixtures_dir = PROJECT_ROOT / "tests" / "fixtures"
    certs_dir = fixtures_dir / "certs"
    packs_dir = fixtures_dir / "evidence_packs"

    if not (certs_dir / "root_ca.pem").exists() or not (packs_dir / "valid_pack.zip").exists():
        print("[*] Generating missing test fixtures...")
        from tests.fixtures.generate_fixtures import main as gen_main
        gen_main()
        print("[+] Test fixtures generated.")


def run_tier(tier: int, verbose: bool = False) -> int:
    """Execute tests for a specific tier using pytest."""
    import pytest

    tier_map = {
        1: [PROJECT_ROOT / "tests" / "e2e" / "test_tier1_features.py"],
        2: [PROJECT_ROOT / "tests" / "e2e" / "test_tier2_boundaries.py"],
        3: [PROJECT_ROOT / "tests" / "e2e" / "test_tier3_combinations.py"],
        4: [PROJECT_ROOT / "tests" / "e2e" / "test_tier4_scenarios.py"],
        5: [
            PROJECT_ROOT / "tests" / "e2e" / "test_tier5_adversarial.py",
            PROJECT_ROOT / "tests" / "e2e" / "test_tier5_adversarial_challenger.py",
        ],
    }

    test_files = tier_map.get(tier, [])
    existing_files = [str(f) for f in test_files if f.exists()]
    if not existing_files:
        print(f"[!] Error: Test files for Tier {tier} not found")
        return 1

    file_names = ", ".join(f.name for f in test_files if f.exists())
    print(f"\n{'='*70}")
    print(f"RUNNING TIER {tier}: {file_names}")
    print(f"{'='*70}")

    args = existing_files
    if verbose:
        args.append("-v")
    else:
        args.append("-q")

    return pytest.main(args)


def main():
    parser = argparse.ArgumentParser(description="Master E2E Test Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4, 5], help="Run specific test tier (1-5)")
    parser.add_argument("--all", action="store_true", default=True, help="Run all 5 tiers (default)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output")
    args = parser.parse_args()

    print("\n" + "="*70)
    print("AI EVIDENCE & ACCOUNTABILITY PLATFORM - E2E TEST SUITE")
    print("="*70)

    ensure_fixtures()

    # Start Mock LLM Server if running in standalone mode
    mock_server = MockLLMServer(host="127.0.0.1", port=0)
    allocated_port = mock_server.start()
    print(f"[+] Mock LLM Server active at http://127.0.0.1:{allocated_port}")

    start_time = time.time()
    results = {}

    try:
        if args.tier:
            tiers_to_run = [args.tier]
        else:
            tiers_to_run = [1, 2, 3, 4, 5]

        for t in tiers_to_run:
            ret_code = run_tier(t, verbose=args.verbose)
            results[f"Tier {t}"] = "PASSED" if ret_code == 0 else f"FAILED (code {ret_code})"

    finally:
        mock_server.stop()
        print("[+] Mock LLM Server terminated.")

    elapsed = time.time() - start_time

    # Summary Report
    print("\n" + "="*70)
    print("TEST SUITE EXECUTION SUMMARY")
    print("="*70)
    all_passed = True
    for tier_name, status in results.items():
        print(f"  * {tier_name:<10}: {status}")
        if "FAILED" in status:
            all_passed = False

    print(f"\nTotal Elapsed Time: {elapsed:.2f}s")

    if all_passed:
        print("\n>>> OVERALL RESULT: ALL E2E TEST TIERS PASSED (100% SUCCESS) <<<\n")
        sys.exit(0)
    else:
        print("\n>>> OVERALL RESULT: SOME TESTS FAILED <<<\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
