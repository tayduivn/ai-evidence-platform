# Enterprise AI Evidence Java SDK (`evidence-client-java`)

High-performance, non-blocking enterprise Java client SDK for the **AI Evidence & Accountability Platform**.

Designed specifically for core banking systems, loan origination engines, credit scoring pipelines, and mission-critical enterprise applications complying with the EU AI Act, Basel III/IV, and SBV regulations.

---

## Key Enterprise Guarantees

1. **Strictly Non-Blocking SLA (< 5.0ms)**:
   - `logDecision(event)` enqueues decision events in an in-memory ring buffer with typical latency **< 0.05ms** (50µs), well below the 5.0ms maximum SLA.
   - Core transaction threads are never stalled by remote network roundtrips or audit logging I/O.

2. **Fault Isolation (Zero Exception Guarantee)**:
   - If the AI Evidence Gateway or Ingest API experiences latency spikes, network partitions, or outages, `logDecision()` drops or buffers events according to policy and **never throws unhandled runtime exceptions** to the caller.
   - Secondary audit logging will never abort or roll back primary transactional database operations.

3. **In-Memory Bounded Ring Buffer**:
   - Backed by `java.util.concurrent.ArrayBlockingQueue` with lock contention minimization and configurable overflow policies (`DROP_NEWEST` or `DROP_OLDEST`).
   - Thread-safe atomic telemetry tracking `enqueued`, `dropped`, and `delivered` events.

4. **Human-in-the-Loop Asynchronous Approval**:
   - Built-in `requestApprovalAsync(event)` returning `CompletableFuture<ApprovalResult>` with non-blocking status polling against `/api/v1/decisions/{id}/status`.
   - Supports 4-eyes separation of duties, anti-rubberstamping dwell time validation, and configurable timeout policies.

5. **Zero Mandatory Third-Party Runtime Dependencies**:
   - Implemented exclusively using standard Java 17 LTS libraries (`java.net.http.HttpClient`, `java.util.concurrent`, `java.time`).
   - Zero classpath collisions, zero transitive dependency vulnerabilities, and instant integration into Spring Boot 3, Quarkus, Micronaut, and Jakarta EE applications.

---

## Installation

### Maven
```xml
<dependency>
    <groupId>com.aievidence</groupId>
    <artifactId>evidence-client-java</artifactId>
    <version>0.3.0</version>
</dependency>
```

---

## Quickstart

### 1. Initialize the Client
```java
import com.aievidence.sdk.EvidenceClient;
import com.aievidence.sdk.ClientConfig;
import com.aievidence.sdk.DropPolicy;

ClientConfig config = ClientConfig.builder()
    .ingestUrl("http://ai-evidence-gateway:8081/api/v1/ml/ingest")
    .aiSystemId("credit-scoring-xgboost")
    .artifactHash("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
    .queueCapacity(10_000)
    .maxBatchSize(50)
    .flushIntervalMs(50)
    .dropPolicy(DropPolicy.DROP_NEWEST)
    .build();

try (EvidenceClient client = EvidenceClient.create(config)) {
    // Application runtime
}
```

### 2. High-Throughput Non-Blocking Decision Logging
```java
import com.aievidence.sdk.model.DecisionEvent;
import java.util.Map;

DecisionEvent event = DecisionEvent.builder()
    .aiSystemId("credit-scoring-xgboost")
    .modelVersion("v2.1.0")
    .score(745.5)
    .decision("APPROVE_LOAN_500M")
    .features(Map.of(
        "income", 45000000L,
        "debt_ratio", 0.28,
        "credit_history_months", 36
    ))
    .correlationId("tx-corr-98214")
    .build();

// Enqueues in < 0.05ms without blocking business logic
boolean enqueued = client.logDecision(event);
```

### 3. Human-in-the-Loop Intercept & Approval Workflow
```java
import com.aievidence.sdk.model.ApprovalResult;
import com.aievidence.sdk.model.ApprovalStatus;
import java.time.Duration;

DecisionEvent highRiskEvent = DecisionEvent.builder()
    .aiSystemId("credit-scoring-xgboost")
    .modelVersion("v2.1.0")
    .score(920.0)
    .decision("HIGH_VALUE_DISBURSEMENT_2B")
    .features(Map.of("loan_amount", 2000000000L))
    .requiresApproval(true)
    .creatorId("loan_officer_01")
    .build();

// Asynchronous non-blocking approval:
client.requestApprovalAsync(highRiskEvent)
    .thenAccept(result -> {
        if (result.isApproved()) {
            System.out.println("Disbursement approved by: " + result.getApprovers());
        } else {
            System.out.println("Rejected: " + result.getRejectionReason());
        }
    });

// Synchronous wait with timeout (for batch / synchronous pipelines):
ApprovalResult syncResult = client.requestApproval(highRiskEvent, Duration.ofSeconds(30));
if (syncResult.isApproved()) {
    // Proceed with disbursement
}
```

---

## Telemetry & Metrics
```java
long enqueued = client.getEnqueuedCount();
long dropped  = client.getDroppedCount();
long delivered = client.getDeliveredCount();
int currentSize = client.getQueueSize();
```

---

## Build & Test
```bash
# Requires JDK 17+
javac -version
# Run unit tests
./run_tests.ps1
```
