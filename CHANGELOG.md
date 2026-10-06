# Changelog

All notable changes to the **AI Evidence & Accountability Platform** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-10-06

### Added
* **Cryptographic Merkle Ingestion**:
  * Implemented RFC 6962 balanced binary Merkle Tree accumulator with domain separation prefixes (`0x00` for leaves, `0x01` for interior nodes).
  * Implemented RFC 8785 JSON Canonicalization Scheme (JCS) serializer for deterministic byte-level hashing across Go, Python, and Java.
  * Added RFC 3161 Time-Stamping Authority (TSA) periodic client for anchoring Merkle roots against external certified UTC atomic clocks.
* **Resilience & Zero-Drop Guarantee**:
  * Integrated in-memory bounded ring-buffer queue (50,000 capacity) achieving $< 5\text{ms}$ (p99) ingestion latency.
  * Implemented Disk Write-Ahead Log (`DiskWAL`) persistent buffer for zero event loss during immudb network partitions or process crashes.
  * Added micro-batching flush engine (50ms interval or 100-event threshold) delivering $> 2,000\text{ events/sec}$ throughput.
* **Governance & Human-in-the-Loop**:
  * 5-state lifecycle approval state machine: `PENDING` $\to$ `UNDER_REVIEW` $\to$ `APPROVED` $\mid$ `REJECTED` $\to$ `EXPIRED`.
  * Strict Four-Eyes Separation of Duties (proposers are cryptographically barred from approving their own decisions).
  * Built-in Dwell Time Engine with millisecond heartbeat verification to prevent automated or hurried rubber-stamping.
  * Granular `KeyMutex` per-item locking mechanism preventing race conditions and parallel double-approvals.
  * Pluggable digital signing architecture supporting Internal RSA-PSS, Vietnamese CA PKCS#11 USB hardware tokens, and VN Remote Signing (Circular 22/2020/TT-BTTTT).
  * Embedded lightweight web console at `:8082` for compliance officers and reviewers.
* **AI Gateway & Security**:
  * Transparent OpenAI-compliant `/v1/chat/completions` proxy engine with streaming SSE support.
  * Automatic Vietnamese PII redactor protecting Citizen ID (CCCD), phone numbers, email addresses, and credit cards.
  * Shadow AI mitigation enforcing `X-AI-System-ID` inspection against `registry.json` whitelist (HTTP 403 on violation).
  * Dual-mode 202 Intercept engine routing high-stakes AI agent decisions into approval workflows with status polling.
* **Client SDKs**:
  * Python Client SDK (`ai_evidence_sdk`) with non-blocking daemon worker, configurable `DropPolicy`, and `ApprovalHandle`.
  * Java Enterprise SDK (`com.aievidence.sdk`) for JDK 17 LTS using asynchronous `CompletableFuture` and zero heavy dependencies.
* **Forensic Tooling**:
  * Standalone, air-gapped forensic verification tool (`ai-evidence-cli`) with subcommands `verify`, `pack`, and `inspect`.
  * Standardized exit codes (`0` to `6`) for automated CI/CD security audit pipelines.
* **Documentation & Testing**:
  * Complete Diataxis documentation suite (14 documents spanning Tutorials, How-To Guides, Reference, and Explanations).
  * Master E2E and adversarial verification test suite with 139/139 passing checks and p95 benchmark $< 15\text{ms}$.

---

## [0.2.0] - 2026-10-05

### Added
* Gateway prototype reverse proxy forwarding chat completion traffic to upstream LLMs.
* Basic immudb client integration using official SDK.
* Initial PII regex scanner for standard emails and generic identification numbers.
* Proof-of-concept 4-Eyes approval HTTP endpoints.
* Standalone mock LLM server generating deterministic streaming and non-streaming responses.

### Changed
* Refactored event envelope schema to support correlation IDs and structured parent links.
* Optimized docker-compose container network configurations.

---

## [0.1.0] - 2026-10-04

### Added
* Project initialization and repository scaffold.
* Core system architecture design specification and threat model.
* Initial Docker Compose configuration with immudb container.
* Basic REST endpoint contracts for Gateway and Ledger Worker.
