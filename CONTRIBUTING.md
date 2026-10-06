# Contributing to AI Evidence & Accountability Platform

Thank you for your interest in contributing to the **AI Evidence & Accountability Platform**! This document provides instructions and standards for developing, testing, and submitting contributions.

---

## 1. Code of Conduct & Development Philosophy

This platform serves as a legal and forensic record for high-stakes AI decisions. All code changes must adhere to:
* **The Non-Blocking Invariant**: Never block the AI application. Ingestion must return in $< 5\text{ms}$.
* **Cryptographic Rigor**: Always preserve canonical RFC 8785 byte order and RFC 6962 tree invariants.
* **Deterministic Behavior**: Avoid non-deterministic UUID/random number generation in hashing routines.
* **Comprehensive Test Coverage**: Every pull request altering business logic must include unit and integration tests.

---

## 2. Prerequisites & Local Environment Setup

Ensure you have the following installed locally:
* **Go**: version `1.23+`
* **Python**: version `3.10+` with `pip` and `virtualenv`
* **Java**: `JDK 17 LTS` and `Maven 3.8+`
* **Docker & Docker Compose**: Docker Engine `24.0+`, Compose `v2.24+`
* **Git**: with standard LF line-endings configured

### Clone & Initialize

```bash
git clone https://github.com/enterprise-intelligence/ai-evidence-platform.git
cd ai-evidence-platform

# Boot supporting cluster (immudb, mock-llm, ledger, gateway, approval)
docker compose up -d --build

# Verify healthy containers
docker compose ps
```

---

## 3. Repository Layout

```
ai-evidence-platform/
├── cli/                         # Go standalone forensic CLI (ai-evidence-cli)
├── docs/                        # Diataxis documentation (Tutorial, How-To, Reference, Explanation)
├── sdks/
│   ├── python/                  # Python Client SDK (Bounded ring buffer, EvidenceClient)
│   └── java/                    # Java Enterprise SDK (JDK 17 LTS, CompletableFuture)
├── services/
│   ├── gateway/                 # Reverse proxy, PII scanner, Shadow AI guard
│   ├── approval/                # 4-Eyes state machine, Dwell Time, Web UI, Signers
│   ├── ledger/                  # Micro-batcher, DiskWAL, RFC 6962 Merkle, immudb client
│   └── mock_llm/                # Upstream OpenAI v1 compatible mock server
├── tests/
│   ├── e2e/                     # End-to-end integration & master verification tests
│   └── fixtures/                # Cryptographic test fixtures, certificates, samples
├── docker-compose.yml           # 5-node production-like cluster definition
├── ARCHITECTURE.md              # System architectural blueprint
└── README.md                    # Root project overview and quick start
```

---

## 4. Coding Standards

### 4.1. Golang (`services/`, `cli/`)
* **Formatting**: Run `gofmt -s -w .` before committing.
* **Error Handling**: Never ignore errors with `_ = ...` unless explicitly documenting why in a comment. Always wrap context with `fmt.Errorf("operation failed: %w", err)`.
* **Goroutine Hygiene**: Every spawned goroutine must monitor a `context.Context` cancellation channel or worker termination signal.
* **Zero-Allocation Logging**: Use structured logging. Avoid string concatenation in hot ingestion paths.

### 4.2. Python (`sdks/python/`, `tests/`)
* **Typing**: Use static type annotations (`typing`) across all public functions and classes.
* **Formatting**: Format code with `black` and check with `flake8`.
* **Thread-Safety**: SDK queues must use `queue.Queue` with non-blocking `put_nowait()` and explicitly handle `queue.Full`.

### 4.3. Java (`sdks/java/`)
* **Target Version**: Java 17 LTS (`--release 17`).
* **Dependency Minimization**: The client SDK must avoid heavy external transitive dependencies. Use built-in `java.net.http.HttpClient` and standard Jackson for JSON processing.
* **Concurrency**: Prefer asynchronous non-blocking pipelines (`CompletableFuture`) over blocking threads.

---

## 5. Verification & Testing Workflow

Before opening a pull request, all test suites must pass cleanly:

### Step 1: Run Go Unit Tests
```bash
# Test all microservices
cd services/gateway && go test -v -race ./... && cd ../..
cd services/ledger && go test -v -race ./... && cd ../..
cd services/approval && go test -v -race ./... && cd ../..

# Test Forensic CLI
cd cli && go test -v -race ./... && cd ..
```

### Step 2: Run Python SDK Tests
```bash
cd sdks/python
pytest tests/ -v --cov=ai_evidence_sdk
cd ../..
```

### Step 3: Run Java SDK Tests
```bash
cd sdks/java
mvn clean test
cd ../..
```

### Step 4: Run E2E Master Verification
Ensure Docker containers are running (`docker compose up -d`), then execute:
```bash
pytest tests/e2e/test_master_verification.py -v
```

---

## 6. Git Branching & Commit Conventions

### Branch Naming Convention
* `feat/<feature-name>`: New capabilities or enhancements.
* `fix/<bug-name>`: Bug fixes or resilience corrections.
* `docs/<topic>`: Documentation updates or Diataxis additions.
* `refactor/<module>`: Refactoring without functional changes.
* `test/<scope>`: Adding or improving test suites.

### Commit Message Format (Conventional Commits)
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary in imperative mood>

[optional detailed body explaining why the change was made]

[optional footer referencing issues or PRs]
```

**Examples:**
* `feat(gateway): add regex pattern for Vietnamese phone numbers`
* `fix(ledger): prevent DiskWAL race condition during container shutdown`
* `docs(how-to): document USB token signing procedure on Windows`
* `test(e2e): add adversarial probe for unauthenticated approvals`

---

## 7. Security & Vulnerability Reporting

If you discover a security vulnerability or cryptographic flaw within this platform:
1. **DO NOT** open a public GitHub issue.
2. Email the maintainer directly at [`huytran@vietcrm.com`](mailto:huytran@vietcrm.com).
3. Provide reproduction steps, potential impact analysis, and proof-of-concept payloads.
4. We acknowledge reports within 24 hours and coordinate patches under a 90-day responsible disclosure policy.
