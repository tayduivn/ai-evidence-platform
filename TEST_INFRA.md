# E2E Test Infrastructure & Methodology: AI Evidence & Accountability Platform

## 1. Testing Methodology & Philosophy

The AI Evidence & Accountability Platform provides an immutable, cryptographically verifiable audit trail for decisions produced by Large Language Models (LLMs) and internal Machine Learning (ML) models.

### 1.1 Opaque-Box E2E Testing Principles
All E2E tests in this suite operate strictly via **public system boundaries and opaque-box interfaces**:
1. **Public Network Protocols**: HTTP REST endpoints, Server-Sent Events (SSE) streaming connections, and gRPC/JSON Ingestion APIs.
2. **Standard CLI Entrypoints**: Standalone binary execution (`ai-evidence-cli verify <evidence_pack>`) capturing exit codes, stdout, and stderr.
3. **Client SDK Contracts**: Public client libraries (`ai_evidence_sdk` Python, `evidence-client-java`) exercising `log_decision()` and `request_approval()`.
4. **Offline Evidence Verification**: Direct cryptographic validation of generated Evidence Pack zip bundles (`manifest.json`, `events.json`, `merkle_proof.json`, digital signatures, X.509 certificate chains, RFC 3161 timestamps).

No test depends on internal memory state, private functions, or mock injection into production service binaries.

### 1.2 The 4-Tier Test Hierarchy
The suite is structured into four progressive tiers to ensure complete coverage, robustness against anomalies, combinatorial correctness, and enterprise workflow fidelity:

```
+-----------------------------------------------------------------------------------+
| Tier 4: Real-World Scenarios (Fintech loan approval, Securities trade audit,      |
|          Air-gapped auditor offline verification)                                 |
+-----------------------------------------------------------------------------------+
| Tier 3: Cross-Feature Combinations (Pairwise interactions: Gateway + Ingest +      |
|          Ledger + 4-Eyes + Signer + Evidence Pack + CLI)                          |
+-----------------------------------------------------------------------------------+
| Tier 2: Boundary & Corner Cases (>=5 tests per feature: empty, 50KB payload,      |
|          invalid CCCD, zero dwell, corrupt zip, single-leaf Merkle, dropped conns)|
+-----------------------------------------------------------------------------------+
| Tier 1: Feature Coverage (>=5 tests per feature: PII, Registry, SSE, Ingest,      |
|          4-Eyes, Dwell Time, Signers, Merkle, CLI, SDKs)                          |
+-----------------------------------------------------------------------------------+
```

- **Tier 1 — Feature Coverage**: Comprehensive unit-to-system verification for each core feature in isolation via public interfaces (minimum 5 test cases per feature).
- **Tier 2 — Boundary & Corner Cases**: Stressing edge conditions, payload limits (0B to 50KB+), malformed PII tokens, timing boundaries, single-transaction Merkle roots, corrupt zip archives, and network disconnects (minimum 5 boundary cases per feature).
- **Tier 3 — Cross-Feature Combinations**: Pairwise and multi-module integration matrix validating that feature interactions (e.g., SSE pass-through with PII redaction and 4-eyes approval intercept) maintain consistency and data integrity.
- **Tier 4 — Real-World Enterprise Scenarios**: Realistic industry workflows simulating high-stakes business flows (Fintech credit loan approval with dual approvals and VN CA signature, Securities compliance trading audit, and air-gapped auditor verification).

---

## 2. Feature Inventory Coverage Mapping

| Feature ID | Feature Name | Tier 1 Tests | Tier 2 Boundaries | Tier 3 Combinations | Tier 4 Scenarios | Target Threshold / SLA |
|---|---|---|---|---|---|---|
| F1 | immudb Event Storage | `test_tier1_immudb_*` (5) | `test_tier2_immudb_*` (5) | Pairwise with Ingest | Scenario 1, 2, 3 | 100% persistence fidelity |
| F2 | Merkle Tree Audit Proofs | `test_tier1_merkle_*` (5) | `test_tier2_merkle_*` (5) | Merkle + CLI | Scenario 2, 3 | Inclusion/Consistency valid |
| F3 | RFC 3161 Anchor Client | `test_tier1_tsa_*` (5) | `test_tier2_tsa_*` (5) | TSA + Evidence Pack | Scenario 2, 3 | Valid ASN.1 TST DER token |
| F4 | Ingestion Queue / Micro-batch | `test_tier1_queue_*` (5) | `test_tier2_queue_*` (5) | Queue + Ingest + immudb | Scenario 1, 2 | 50ms batch window |
| F5 | AI Gateway Reverse Proxy | `test_tier1_gateway_*` (5) | `test_tier2_gateway_*` (5) | Gateway + PII + Registry | Scenario 1, 2 | Transparent reverse proxy |
| F6 | SSE Token Pass-Through & Acc | `test_tier1_sse_*` (5) | `test_tier2_sse_*` (5) | SSE + PII + Audit | Scenario 1, 2 | Zero chunk delay, exact acc |
| F7 | Vietnamese PII Scanner | `test_tier1_pii_*` (5) | `test_tier2_pii_*` (5) | PII + SSE + Gateway | Scenario 1 | 12-digit CCCD, Phone, Bank STK |
| F8 | AI Registry & Shadow AI Reject | `test_tier1_registry_*` (5) | `test_tier2_registry_*` (5) | Registry + Dual Mode | Scenario 1, 2 | Unregistered returns 403 |
| F9 | Gateway Dual Modes | `test_tier1_dual_mode_*` (5) | `test_tier2_dual_mode_*` (5) | Audit vs 202 Intercept | Scenario 1, 2 | 202 Accepted + poll URL |
| F10 | ML Ingest Endpoint | `test_tier1_ml_ingest_*` (5) | `test_tier2_ml_ingest_*` (5) | ML Ingest + Signer | Scenario 1 | Features/score/SHAP stored |
| F11 | Approval State Machine | `test_tier1_approval_*` (5) | `test_tier2_approval_*` (5) | Approval + 4-Eyes | Scenario 1 | PENDING->APPROVED/REJECTED |
| F12 | 4-Eyes Principle Engine | `test_tier1_four_eyes_*` (5) | `test_tier2_four_eyes_*` (5) | 4-Eyes + Signers | Scenario 1, 2 | Creator cannot self-approve |
| F13 | Anti-Rubberstamping Dwell Time | `test_tier1_dwell_time_*` (5) | `test_tier2_dwell_time_*` (5) | Dwell Time + UI + Approval| Scenario 1 | Reject approval if dwell < min |
| F14 | Pluggable Signer Interface | `test_tier1_signer_*` (5) | `test_tier2_signer_*` (5) | Signer + Evidence Pack | Scenario 1, 2, 3 | Internal, CA VN token/remote |
| F15 | Canonical Payload Serializer | `test_tier1_canonical_*` (5) | `test_tier2_canonical_*` (5) | Serializer + Signer | Scenario 1, 2, 3 | RFC 8785 deterministic JSON |
| F16 | Approval Web UI | `test_tier1_ui_*` (5) | `test_tier2_ui_*` (5) | UI + Dwell + Signer | Scenario 1 | Render diffs, SHAP, badge |
| F17 | Evidence Pack Archive Builder | `test_tier1_pack_builder_*` (5)| `test_tier2_pack_builder_*` (5)| Pack + CLI | Scenario 2, 3 | Zip format with manifest |
| F18 | Standalone Offline CLI | `test_tier1_cli_*` (5) | `test_tier2_cli_*` (5) | CLI + Corrupted Pack | Scenario 3 | Exit code 0 on valid pack |
| F19 | Offline Verification Engine | `test_tier1_verifier_*` (5) | `test_tier2_verifier_*` (5) | Verifier + Air-gapped | Scenario 3 | VERIFICATION_SUCCESS emitted |
| F20 | Python SDK Non-Blocking Engine| `test_tier1_py_sdk_*` (5) | `test_tier2_py_sdk_*` (5) | SDK + Ingest failure | Scenario 1 | < 5ms return on offline API |
| F21 | Python SDK Approval Workflow | `test_tier1_py_approval_*` (5)| `test_tier2_py_approval_*` (5)| SDK + 4-Eyes Webhook | Scenario 1 | Polling/webhook completion |
| F22 | Java SDK Client Contract | `test_tier1_java_sdk_*` (5) | `test_tier2_java_sdk_*` (5) | Java SDK + Queue | Scenario 2 | Bounded queue & CompletableFuture|
| F23 | Docker Compose Cluster Stack | `test_tier1_compose_*` (5) | `test_tier2_compose_*` (5) | Cluster orchestration | Scenario 1, 2, 3 | Multi-service health endpoints |
| F24 | Mock LLM Service | `test_tier1_mock_llm_*` (5) | `test_tier2_mock_llm_*` (5) | Mock LLM + Gateway | Scenario 1, 2 | SSE chunks + latency/error inj |
| F25 | E2E Opaque-Box Suite Runner | `test_tier1_runner_*` (5) | `test_tier2_runner_*` (5) | Full suite execution | Scenario 1, 2, 3 | Exit 0 on 100% pass |
| F26 | Python SDK Resilience Harness | `test_tier1_resilience_*` (5)| `test_tier2_resilience_*` (5)| Downed Ingest + Spikes | Scenario 1 | 0 unhandled exceptions |
| F27 | Gateway Latency Benchmark | `test_tier1_benchmark_*` (5) | `test_tier2_benchmark_*` (5)| 50KB payload overhead | Benchmark suite | p95 overhead < 15ms |
| F28 | Adversarial Tamper Verification| `test_tier1_adversarial_*` (5)| `test_tier2_adversarial_*` (5)| Tampered root, hash, cert| Scenario 3 | Exit code 1-5 on tamper |

---

## 3. Directory Layout

```
c:\Users\huytv\Desktop\tmp\ei-evidence-platform\
├── services/
│   └── mock_llm/
│       ├── __init__.py           # Package indicator
│       ├── server.py             # HTTP & SSE streaming mock server with fault injection
│       ├── test_mock_llm.py      # Self-verification tests for mock LLM
│       └── README.md             # Usage documentation
├── tests/
│   ├── fixtures/
│   │   ├── certs/                # Self-signed Root CA and approver certificates
│   │   ├── evidence_packs/       # Valid, tampered, and corrupt evidence pack archives
│   │   └── payloads/             # 50KB payloads, Vietnamese PII fixtures, ML feature sets
│   ├── e2e/
│   │   ├── __init__.py
│   │   ├── conftest.py           # Shared fixtures, client sessions, mock servers
│   │   ├── test_tier1_features.py       # Tier 1: Feature coverage (>=5 per feature)
│   │   ├── test_tier2_boundaries.py     # Tier 2: Boundary & corner cases (>=5 per feature)
│   │   ├── test_tier3_combinations.py   # Tier 3: Cross-feature pairwise interactions
│   │   ├── test_tier4_scenarios.py      # Tier 4: Real-world high-stakes workflows
│   │   └── run_tests.py                 # Standalone master runner script
├── TEST_INFRA.md                 # This specification document
└── TEST_READY.md                 # Readiness manifest & execution proof
```

---

## 4. Test Execution Models & Environment Modes

### 4.1 Execution Modes
1. **Live Cluster Mode (`--mode=live`)**:
   Runs against live Docker Compose services (Gateway at `http://localhost:8080`, Ingest at `http://localhost:8081`, Approval UI/API at `http://localhost:8082`, immudb at `localhost:3322`).
2. **Contract & Standalone Mock Mode (`--mode=mock`, Default)**:
   Runs self-contained against the integrated `services/mock_llm/` and local contract test engines. Can run in any CI/CD environment without requiring external Docker dependencies or privileged ports.

### 4.2 Progressive Testability
During milestone execution:
- Tests verify interface contracts independently.
- When an upstream service is not yet deployed, the test harness verifies contract schema compatibility, cryptographic invariant calculations (Merkle root, RFC 8785 canonical hash, X.509 signature verification), and behavioral error codes.
- The suite never fails due to missing optional components; it asserts strict compliance against the published contracts in `PROJECT.md`.

---

## 5. Thresholds, SLAs & Verification Assertions

1. **Gateway Latency Overhead SLA**:
   - Direct Mock LLM vs Gateway Reverse Proxy latency difference for 50KB payload:
     $$\Delta \text{Latency}_{p95} < 15\text{ms}$$
2. **Python SDK Non-Blocking Guarantee**:
   - `log_decision()` call duration during normal operations or total network failure:
     $$T_{\text{exec}} < 5\text{ms}$$
   - No exceptions raised to caller under HTTP 500, network timeout, or connection refused.
3. **Vietnamese PII Detection & Redaction Accuracy**:
   - 100% detection and masking of 12-digit CCCD (`001090012345` -> `001******345` or `[CCCD_REDACTED]`).
   - 100% detection and masking of Vietnamese phone numbers (`0912345678`, `+84988776655`).
   - 100% detection of bank account numbers in financial context.
4. **AI Registry Authorization Enforcement**:
   - Unregistered `X-AI-System-ID` or missing header -> HTTP 403 Forbidden.
   - Prompt hash or model artifact hash mismatch -> HTTP 403 Forbidden.
5. **Human-in-the-Loop & 4-Eyes Integrity**:
   - Creator self-approval -> HTTP 400 / 403 with `CREATOR_CANNOT_APPROVE`.
   - Approver 2 == Approver 1 -> HTTP 400 / 403 with `DUPLICATE_APPROVER`.
   - Approval attempt prior to minimum dwell time -> HTTP 400 / 422 with `DWELL_TIME_NOT_MET`.
6. **Offline CLI Verification Determinism**:
   - Valid Evidence Pack -> Exit code 0, emits `VERIFICATION_SUCCESS`.
   - Corrupted Manifest / Tampered Event -> Exit code 1.
   - Corrupted Merkle Proof -> Exit code 2.
   - Invalid Digital Signature -> Exit code 3.
   - Expired or Untrusted Certificate -> Exit code 4.
   - 4-Eyes or Dwell Time Policy Violation -> Exit code 5.
