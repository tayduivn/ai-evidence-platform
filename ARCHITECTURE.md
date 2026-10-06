# Architecture Blueprint: AI Evidence & Accountability Platform (v0.3)

> **Document Classification**: Technical Architecture Design Document  
> **Target Audience**: System Architects, Security Engineers, Lead Developers, Enterprise Auditors  
> **Status**: Approved & Baselined (v0.3.0)

---

## 1. System Mission & Architectural Tenets

The **AI Evidence & Accountability Platform** provides tamper-evident, forensically sound audit trails for Generative AI applications and autonomous multi-agent systems. It operates in high-stakes regulated domains (banking, healthcare, legal compliance, critical infrastructure) subject to the **EU AI Act**, **ISO/IEC 42001**, and Vietnam's **Decree 13/2023/ND-CP**.

### The Core Architectural Tenets

1. **The Zero-Drop Non-Blocking Invariant**: Logging and governance must **never** degrade AI inference latency or cause cascading failures in the primary AI application. Ingestion SLA is strictly guaranteed under **5ms (p99)**.
2. **Cryptographic Tamper-Evidence**: Audit records are organized into append-only cryptographic structures (RFC 6962 Merkle Trees) with deterministic byte canonicalization (RFC 8785 JCS) and anchored to external Time-Stamping Authorities (RFC 3161 TSA).
3. **Four-Eyes Separation of Duties**: Critical autonomous actions require out-of-band human sign-off where the proposer cannot approve their own submission, backed by anti-rubber-stamping Dwell Time verification.
4. **Air-Gapped Forensic Portability**: Evidence can be packaged into self-contained, portable zip archives and verified offline by third-party auditors using a standalone zero-dependency CLI.

---

## 2. High-Level Component Topology

```mermaid
flowchart TD
    subgraph ExternalClients["Clients & Consumers"]
        App["AI Agent / Core Application"]
        PySDK["Python SDK (EvidenceClient)"]
        JavaSDK["Java SDK (EvidenceClient)"]
        Auditor["Forensic Auditor / Legal"]
    end

    subgraph EdgeBoundary["Network Edge & AI Gateway (:8081)"]
        ReverseProxy["OpenAI Proxy Engine"]
        PIIScanner["PDPD / PII Masking Engine"]
        ShadowGuard["Shadow AI Guard (registry.json)"]
        IngestAPI["ML Ingest REST API"]
    end

    subgraph GovernanceBoundary["Human-in-the-Loop Governance (:8082)"]
        ApprovalSM["4-Eyes State Machine"]
        DwellEngine["Dwell Time Engine (KeyMutex)"]
        SignerModule["Pluggable Signer (RSA-PSS / VN Token / Remote)"]
        WebConsole["Embedded Management Console"]
    end

    subgraph LedgerBoundary["Storage & Ingestion Tier (:8083 & :3324)"]
        RingBuffer["Ring-Buffer (Bounded Queue 50k)"]
        DiskWAL["Disk Write-Ahead Log (WAL)"]
        BatchEngine["Micro-Batcher (50ms / 100 items)"]
        MerkleEngine["RFC 6962 Merkle Accumulator"]
        ImmudbStore[("immudb Cryptographic DB (:3324)")]
    end

    subgraph ExternalTrust["External Trust Anchors"]
        TSA["RFC 3161 TSA (FreeTSA / DigiCert)"]
        MockLLM["Upstream LLM Provider (:8080)"]
    end

    subgraph ForensicArtifacts["Offline Verification Tier"]
        Pack[("Evidence Pack (.zip)")]
        CLI["ai-evidence-cli"]
    end

    App -->|1. Chat Completion| ReverseProxy
    ReverseProxy -->|2. Verify System ID| ShadowGuard
    ReverseProxy -->|3. Redact Sensitive Fields| PIIScanner
    PIIScanner -->|4. Forward Request| MockLLM
    MockLLM -->|5. Stream Response| ReverseProxy
    ReverseProxy -->|6. Async Fire-and-Forget| RingBuffer

    App -->|7. High-Stakes Action (202 Intercept)| ApprovalSM
    ApprovalSM <-->|8. Enforce Dwell Time & Review| DwellEngine
    DwellEngine -->|9. Sign Approved Manifest| SignerModule
    SignerModule -->|10. Audit Event| RingBuffer

    PySDK & JavaSDK -.->|Direct Ingestion| IngestAPI
    IngestAPI -->|Async Enqueue| RingBuffer

    RingBuffer -->|11. Ingest Batches| BatchEngine
    RingBuffer -.->|Overflow / Ingestion Error| DiskWAL
    DiskWAL -.->|Replay on Reconnect| BatchEngine
    BatchEngine -->|12. Compute Tree| MerkleEngine
    BatchEngine -->|13. Commit Append-Only| ImmudbStore

    MerkleEngine -.->|14. Periodic Anchor| TSA
    ImmudbStore -.->|15. Export Audit Trail| Pack
    Pack -.->|16. Zero-Network Validation| CLI
    Auditor -.->|17. Execute Verify| CLI
```

---

## 3. Tiered Component Responsibilities

### 3.1. AI Gateway (`services/gateway` - Port 8081)
Written in Go (1.23+), the Gateway sits transparently between user clients and upstream LLMs:
* **Protocol Compatibility**: Exposes OpenAI-compliant `/v1/chat/completions` endpoints.
* **PII Redaction**: Regular expression scanner intercepting Vietnamese Citizen Identity Cards (CCCD 12 digits), phone numbers (`0[3|5|7|8|9]xxxxxxx`), emails, and credit cards before external forwarding.
* **Shadow AI Mitigation**: Intercepts all requests and inspects `X-AI-System-ID` against a dynamic `registry.json` whitelist. Unregistered or unauthorized systems receive HTTP 403 Forbidden.
* **Dual-Mode 202 Interception**: Detects high-risk agent intents (e.g., loan approvals > \$10k, privileged data access) and returns `HTTP 202 Accepted` with a `poll_url` while routing the decision to the Approval Service.

### 3.2. Human Approval Service (`services/approval` - Port 8082)
A stateful service enforcing the **Four-Eyes Principle**:
* **State Machine**: Strict progression: `PENDING` $\to$ `UNDER_REVIEW` $\to$ `APPROVED` $\mid$ `REJECTED` $\to$ `EXPIRED`.
* **Dwell Time Engine**: Enforces a mandatory minimum review window (configurable, default 15s) using millisecond-precision heartbeats to prevent automated rubber-stamping.
* **KeyMutex Concurrency Guard**: Fine-grained per-item locking prevents race conditions and parallel double-approvals without bottlenecking unrelated approvals.
* **Digital Signer Strategy**: Pluggable interface supporting:
  1. *Internal RSA-PSS / SHA-256*: High-throughput software signing.
  2. *VN CA PKCS#11*: Hardware USB Crypto-Tokens (VNPT, Viettel, FPT).
  3. *VN Remote Signing*: Cloud HSM via REST API compliant with Circular 22/2020/TT-BTTTT.

### 3.3. Ledger Worker (`services/ledger` - Port 8083)
The cryptographic ingestion engine:
* **Micro-Batching**: Flushes batches every 50ms or when reaching 100 events, achieving throughput > 2,000 events/sec.
* **Ring-Buffer Non-Blocking Queue**: In-memory ring buffer (default capacity: 50,000) that isolates ingress HTTP requests from database I/O.
* **Disk Write-Ahead Log (WAL)**: Fallback mechanism storing uncommitted events in append-only binary files on disk if immudb becomes unavailable, replaying them automatically upon reconnection.
* **RFC 6962 Merkle Tree Engine**: Computes incremental SHA-256 leaf and interior nodes using standard domain-separation prefixes (`0x00` for leaves, `0x01` for interior nodes).

### 3.4. Cryptographic Storage (`immudb` - Ports 3324 / 3322)
* Provides cryptographic append-only state backed by an internal Merkle tree.
* Rejects modifications or deletions at the storage engine level.
* Supports cryptographic proofs of inclusion and consistency.

### 3.5. Standalone Forensic CLI (`cli/` - `ai-evidence-cli`)
* Compiled into a single self-contained binary.
* Requires **zero network access** and **zero database credentials**.
* Parses evidence ZIP archives, validates RFC 8785 canonical hashes, recomputes the Merkle root, checks RSA/ECDSA digital signatures, and verifies RFC 3161 timestamps.

---

## 4. Cryptographic Pipeline & Data Invariants

### 4.1. Event Canonicalization (RFC 8785 JCS)
To eliminate non-deterministic JSON serialization across different languages (Go, Python, Java), every event envelope is canonicalized before hashing:
$$\text{LeafHash} = \text{SHA-256}(0x00 \parallel \text{JCS}(E))$$
* Keys are sorted lexicographically by UTF-16 code units.
* Whitespace outside strings is stripped.
* Floats and numbers follow strict ECMAScript 6 formatting rules.

### 4.2. RFC 6962 Merkle Tree Construction
Leaves are combined into a balanced binary tree:
$$\text{NodeHash} = \text{SHA-256}(0x01 \parallel \text{LeftChildHash} \parallel \text{RightChildHash})$$
* Interior nodes use the `0x01` prefix to defend against second-preimage attacks.
* Incremental tree proofs allow proving an event $E_i$ belongs to root $R$ in $O(\log N)$ space and time.

### 4.3. RFC 3161 External Time-Stamping
Every hour (configurable), the Ledger Worker exports the latest Merkle Root $R_k$ and submits a Time-Stamp Request (TSR) to an external TSA. The resulting Time-Stamp Response (TST) binds the root to a certified UTC atomic clock time.

---

## 5. Security & Trust Boundaries

```
[ UNTRUSTED ZONE ]
   AI User / Chat Client / External Mobile App
──────────────────────────────────────────────────── [ Boundary 1: TLS + API Key + System-ID ]
[ EDGE DMZ ]
   AI Gateway (:8081)
   • Sanitizes PII
   • Drops Shadow AI Traffic
──────────────────────────────────────────────────── [ Boundary 2: Internal Docker Bridge ]
[ TRUSTED CORE ]
   Ledger Worker (:8083)    Approval Service (:8082)    immudb (:3324)
   • Memory Ring-Buffer     • 4-Eyes RBAC              • Cryptographic Store
   • DiskWAL Storage        • USB Token / HSM
──────────────────────────────────────────────────── [ Boundary 3: Air-Gap Boundary ]
[ AUDIT ZONE ]
   Isolated Forensic Laptop / Third-Party Auditor
   • ai-evidence-cli (Read-only, Zero-Network)
```

---

## 6. Resilience & High-Availability Model

| Component | Failure Mode | Resilience Mechanism | Recovery Behavior |
|:---|:---|:---|:---|
| **immudb** | Process crash, network partition, disk full | In-memory Ring Buffer holds up to 50k events; spills to local DiskWAL | Auto-detects reconnection, replays WAL sequentially, flushes to immudb |
| **Ledger Worker** | Worker container crash | Upstream Gateway uses non-blocking retry buffer; uncommitted WAL persisted in Docker volume | Container restarts, recovers WAL state from `/var/lib/ledger/wal` |
| **AI Gateway** | High request burst (>10,000 req/s) | Bounded queue with configurable `DropPolicy` (DropOldest / DropNewest) | Ingest latency remains < 5ms; logs warning metric; zero crash |
| **Approval UI** | Reviewer closes browser during review | Heartbeat mechanism expires review state | Locks release automatically; state reverts to `PENDING` |
| **TSA Authority** | External TSA server unreachable | Anchor Service logs soft warning and falls back to internal clock | Retries on next scheduled window; immudb integrity unaffected |

---

## 7. Technology Stack & Protocol Matrix

| Layer | Technology | Version | Rationale |
|:---|:---|:---|:---|
| **Core Services** | Go (Golang) | `1.23+` | High-concurrency goroutines, minimal memory footprint, zero GC latency spikes. |
| **Immutable Storage** | immudb | `1.9.5` | Cryptographic tamper-proofing, zero-knowledge verification proofs. |
| **Client SDK (Python)** | Python | `3.10+` | Bounded thread-safe queue, zero blocking for PyTorch/LangChain/LlamaIndex. |
| **Client SDK (Java)** | Java / Maven | `JDK 17 LTS` | Enterprise compatibility, non-blocking `CompletableFuture`, Netty-grade memory handling. |
| **Forensic CLI** | Go | `1.23+` | Single static binary, no runtime dependencies, runs in air-gapped forensic environments. |
| **Orchestration** | Docker & Compose | `v2.24+` | Declarative 5-node topology, automated healthchecks, volume persistence. |
