package com.aievidence.sdk;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * EMPIRICAL ADVERSARIAL STRESS & CHALLENGE HARNESS
 *
 * Authored by challenger_m5_2 to empirically probe:
 * 1. Strict Latency SLA Benchmark (< 5.0ms under 10 threads, 5,000 requests).
 * 2. Network Outage Fault Isolation (dead port 59999, connection resets, zero exception leakage).
 * 3. Queue Overflow & Telemetry Invariant Conservation (DROP_NEWEST, DROP_OLDEST under concurrency).
 * 4. CompletableFuture Lifecycle & Timeout Behavior (slow servers, terminal state completion, ApprovalTimeoutException).
 */
public class AdversarialChallengeTest {

    public static void main(String[] args) throws Throwable {
        System.out.println("======================================================================");
        System.out.println("ADVERSARIAL CHALLENGE HARNESS: ENTERPRISE JAVA SDK (sdks/java/)");
        System.out.println("======================================================================");
        new AdversarialChallengeTest().runAll();
        System.out.println("\n>>> [PASS] AdversarialChallengeTest: All 8 challenge tests passed. <<<");
    }

    public void runAll() throws Throwable {
        challengeLatencySlaUnderConcurrency();
        challengeLatencySlaUnderQueueBackpressure();
        challengeNetworkOutageFaultIsolationDeadPort();
        challengeNetworkOutageAsyncAndFlushFaultIsolation();
        challengeQueueOverflowDropNewestInvariants();
        challengeQueueOverflowDropOldestOrderingAndInvariants();
        challengeApprovalCompletableFutureTerminalStateLifecycle();
        challengeApprovalCompletableFutureTimeoutAndExceptionLifecycle();
    }

    // =========================================================================
    // MANDATE 1: LATENCY SLA STRESS TEST (< 5.0ms under multi-threaded concurrency)
    // =========================================================================

    public void challengeLatencySlaUnderConcurrency() throws Throwable {
        System.out.println("\n[*] Challenge 1A: Latency SLA under Multi-Threaded Concurrency (10 threads, 5,000 requests)...");

        final int threadCount = 10;
        final int requestsPerThread = 500;
        final int totalRequests = threadCount * requestsPerThread;

        ClientConfig config = ClientConfig.builder()
                .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                .aiSystemId("challenge-latency-system")
                .queueCapacity(20_000)
                .maxBatchSize(100)
                .flushIntervalMs(50)
                .build();

        try (EvidenceClient client = EvidenceClient.create(config)) {
            DecisionEvent event = DecisionEvent.builder()
                    .aiSystemId("challenge-latency-system")
                    .modelVersion("v2.5.0")
                    .score(840.5)
                    .decision("AUTO_APPROVE")
                    .features(Map.of(
                            "applicant_income", 60_000_000L,
                            "debt_to_income", 0.22,
                            "credit_bureau_score", 760
                    ))
                    .correlationId("tx-bench-warmup")
                    .build();

            // Warm up JVM / JIT
            for (int i = 0; i < 500; i++) {
                client.logDecision(event);
            }

            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch readyLatch = new CountDownLatch(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);

            long[][] durationsNs = new long[threadCount][requestsPerThread];
            AtomicInteger failureCount = new AtomicInteger(0);
            AtomicInteger rejectedCount = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                final int threadIdx = t;
                executor.submit(() -> {
                    readyLatch.countDown();
                    try {
                        startLatch.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }

                    for (int i = 0; i < requestsPerThread; i++) {
                        DecisionEvent ev = DecisionEvent.builder()
                                .aiSystemId("challenge-latency-system")
                                .score(750.0 + (i % 100))
                                .correlationId("tx-sla-" + threadIdx + "-" + i)
                                .build();

                        long start = System.nanoTime();
                        boolean accepted = client.logDecision(ev);
                        long elapsed = System.nanoTime() - start;

                        durationsNs[threadIdx][i] = elapsed;

                        if (!accepted) {
                            rejectedCount.incrementAndGet();
                        }
                        if (elapsed >= 5_000_000L) { // 5.0ms SLA
                            failureCount.incrementAndGet();
                        }
                    }
                    doneLatch.countDown();
                });
            }

            readyLatch.await(5, TimeUnit.SECONDS);
            long overallStart = System.currentTimeMillis();
            startLatch.countDown();
            boolean completed = doneLatch.await(15, TimeUnit.SECONDS);
            long overallElapsed = System.currentTimeMillis() - overallStart;

            executor.shutdownNow();

            if (!completed) {
                throw new AssertionError("Concurrency test did not complete within 15 seconds deadline");
            }

            // Aggregate metrics across all 5,000 measurements
            long[] allDurations = new long[totalRequests];
            int idx = 0;
            for (int t = 0; t < threadCount; t++) {
                for (int i = 0; i < requestsPerThread; i++) {
                    allDurations[idx++] = durationsNs[t][i];
                }
            }
            Arrays.sort(allDurations);

            double minMs = allDurations[0] / 1_000_000.0;
            double p50Ms = allDurations[(int) (totalRequests * 0.50)] / 1_000_000.0;
            double p95Ms = allDurations[(int) (totalRequests * 0.95)] / 1_000_000.0;
            double p99Ms = allDurations[(int) (totalRequests * 0.99)] / 1_000_000.0;
            double maxMs = allDurations[totalRequests - 1] / 1_000_000.0;

            System.out.printf("    Concurrency Metrics (10 threads, 5,000 calls in %dms):%n", overallElapsed);
            System.out.printf("    min=%.4fms, p50=%.4fms, p95=%.4fms, p99=%.4fms, max=%.4fms%n",
                    minMs, p50Ms, p95Ms, p99Ms, maxMs);
            System.out.printf("    SLA Violations (> 5.0ms): %d, Buffer Rejections: %d%n",
                    failureCount.get(), rejectedCount.get());

            if (failureCount.get() > 0) {
                throw new AssertionError(String.format(
                        "SLA VIOLATION: %d calls out of %d exceeded the 5.0ms threshold. Max latency was %.4fms",
                        failureCount.get(), totalRequests, maxMs));
            }
            if (maxMs >= 5.0) {
                throw new AssertionError(String.format("Max latency %.4fms violates < 5.0ms SLA", maxMs));
            }
            if (rejectedCount.get() > 0) {
                throw new AssertionError(String.format("Unexpected rejections with queue capacity 20,000: %d", rejectedCount.get()));
            }

            System.out.println("  [PASS] Challenge 1A: 100% of 5,000 calls returned in < 5.0ms SLA under 10 concurrent threads.");
        }
    }

    public void challengeLatencySlaUnderQueueBackpressure() throws Throwable {
        System.out.println("\n[*] Challenge 1B: Latency SLA under Saturated Queue Backpressure (DROP_NEWEST & DROP_OLDEST)...");

        final int smallCapacity = 50;
        final int overflowCalls = 2_000;

        // Test DROP_NEWEST backpressure latency
        {
            ClientConfig config = ClientConfig.builder()
                    .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                    .queueCapacity(smallCapacity)
                    .dropPolicy(DropPolicy.DROP_NEWEST)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder().aiSystemId("sys-bp").score(100.0).build();

                for (int i = 0; i < smallCapacity; i++) {
                    client.logDecision(event);
                }

                long maxNs = 0;
                int violations = 0;
                for (int i = 0; i < overflowCalls; i++) {
                    long start = System.nanoTime();
                    boolean accepted = client.logDecision(event);
                    long elapsed = System.nanoTime() - start;

                    if (elapsed > maxNs) maxNs = elapsed;
                    if (elapsed >= 5_000_000L) violations++;
                }

                double maxMs = maxNs / 1_000_000.0;
                System.out.printf("    DROP_NEWEST backpressure max latency across %d calls: %.4fms (violations=%d)%n",
                        overflowCalls, maxMs, violations);
                if (violations > 0 || maxMs >= 5.0) {
                    throw new AssertionError("DROP_NEWEST backpressure exceeded 5.0ms SLA: max=" + maxMs + "ms");
                }
            }
        }

        // Test DROP_OLDEST backpressure latency
        {
            ClientConfig config = ClientConfig.builder()
                    .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                    .queueCapacity(smallCapacity)
                    .dropPolicy(DropPolicy.DROP_OLDEST)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder().aiSystemId("sys-bp").score(100.0).build();

                for (int i = 0; i < smallCapacity; i++) {
                    client.logDecision(event);
                }

                long maxNs = 0;
                int violations = 0;
                for (int i = 0; i < overflowCalls; i++) {
                    long start = System.nanoTime();
                    boolean accepted = client.logDecision(event);
                    long elapsed = System.nanoTime() - start;

                    if (elapsed > maxNs) maxNs = elapsed;
                    if (elapsed >= 5_000_000L) violations++;
                }

                double maxMs = maxNs / 1_000_000.0;
                System.out.printf("    DROP_OLDEST backpressure max latency across %d calls: %.4fms (violations=%d)%n",
                        overflowCalls, maxMs, violations);
                if (violations > 0 || maxMs >= 5.0) {
                    throw new AssertionError("DROP_OLDEST backpressure exceeded 5.0ms SLA: max=" + maxMs + "ms");
                }
            }
        }

        System.out.println("  [PASS] Challenge 1B: Backpressure rejection and eviction execute well within < 5.0ms SLA.");
    }

    // =========================================================================
    // MANDATE 2: NETWORK OUTAGE FAULT ISOLATION (dead port 59999)
    // =========================================================================

    public void challengeNetworkOutageFaultIsolationDeadPort() throws Throwable {
        System.out.println("\n[*] Challenge 2A: Network Outage Fault Isolation on Dead Port 59999 (2,000 high-volume requests)...");

        String deadUrl = "http://127.0.0.1:59999/api/v1/ml/ingest";

        ClientConfig config = ClientConfig.builder()
                .ingestUrl(deadUrl)
                .aiSystemId("dead-port-isolation")
                .queueCapacity(500)
                .flushIntervalMs(10)
                .httpTimeoutMs(100)
                .build();

        try (EvidenceClient client = EvidenceClient.create(config)) {
            final int threads = 8;
            final int perThread = 250;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch latch = new CountDownLatch(threads);
            AtomicInteger exceptionCount = new AtomicInteger(0);

            for (int t = 0; t < threads; t++) {
                final int tid = t;
                pool.submit(() -> {
                    try {
                        for (int i = 0; i < perThread; i++) {
                            DecisionEvent ev = DecisionEvent.builder()
                                    .aiSystemId("dead-port-isolation")
                                    .score(500.0 + i)
                                    .correlationId("tx-dead-" + tid + "-" + i)
                                    .build();

                            client.logDecision(ev);
                        }
                    } catch (Throwable ex) {
                        exceptionCount.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            boolean finished = latch.await(10, TimeUnit.SECONDS);
            pool.shutdownNow();

            if (!finished) {
                throw new AssertionError("Multi-threaded outage logging timed out");
            }
            if (exceptionCount.get() > 0) {
                throw new AssertionError("FAULT ISOLATION BREACH: " + exceptionCount.get() + " exceptions leaked to caller threads!");
            }

            System.out.printf("    Sent %d requests to dead endpoint %s: 0 exceptions leaked.%n",
                    threads * perThread, deadUrl);
            System.out.println("  [PASS] Challenge 2A: Zero exceptions leaked to caller threads during dead-port network outage.");
        }
    }

    public void challengeNetworkOutageAsyncAndFlushFaultIsolation() throws Throwable {
        System.out.println("\n[*] Challenge 2B: Async logging, flush(), and close() Fault Isolation on Dead Port 59999...");

        String deadUrl = "http://127.0.0.1:59999/api/v1/ml/ingest";

        ClientConfig config = ClientConfig.builder()
                .ingestUrl(deadUrl)
                .aiSystemId("dead-port-async")
                .queueCapacity(200)
                .flushIntervalMs(20)
                .httpTimeoutMs(100)
                .build();

        try (EvidenceClient client = EvidenceClient.create(config)) {
            DecisionEvent event = DecisionEvent.builder()
                    .aiSystemId("dead-port-async")
                    .score(600.0)
                    .correlationId("tx-async-dead")
                    .build();

            for (int i = 0; i < 50; i++) {
                CompletableFuture<Boolean> future = client.logDecisionAsync(event);
                if (future == null) {
                    throw new AssertionError("logDecisionAsync must return non-null CompletableFuture");
                }
                Boolean accepted = future.join();
                if (accepted == null) {
                    throw new AssertionError("Future completed with null");
                }
            }

            long start = System.currentTimeMillis();
            boolean flushed = client.flush(Duration.ofMillis(250));
            long elapsed = System.currentTimeMillis() - start;

            System.out.printf("    flush(250ms) against dead port finished in %dms (flushed=%b)%n", elapsed, flushed);
            if (elapsed > 1000) {
                throw new AssertionError("flush() took too long to return under network outage: " + elapsed + "ms");
            }

            long closeStart = System.currentTimeMillis();
            client.close();
            long closeElapsed = System.currentTimeMillis() - closeStart;

            System.out.printf("    close() against dead port finished in %dms%n", closeElapsed);
            if (closeElapsed > 3000) {
                throw new AssertionError("close() hung during network outage: " + closeElapsed + "ms");
            }

            System.out.println("  [PASS] Challenge 2B: logDecisionAsync, flush, and close are completely fault-isolated.");
        }
    }

    // =========================================================================
    // MANDATE 3: QUEUE OVERFLOW & TELEMETRY INVARIANTS (DROP_NEWEST, DROP_OLDEST)
    // =========================================================================

    public void challengeQueueOverflowDropNewestInvariants() throws Throwable {
        System.out.println("\n[*] Challenge 3A: Bounded Queue Overflow Invariants under DROP_NEWEST...");

        final int capacity = 100;
        final int producers = 10;
        final int perProducer = 200;
        final int totalSubmissions = producers * perProducer; // 2,000

        BoundedEventQueue queue = new BoundedEventQueue(capacity, DropPolicy.DROP_NEWEST);

        ExecutorService pool = Executors.newFixedThreadPool(producers);
        CountDownLatch latch = new CountDownLatch(producers);
        AtomicInteger acceptedCount = new AtomicInteger(0);
        AtomicInteger rejectedCount = new AtomicInteger(0);

        for (int p = 0; p < producers; p++) {
            final int pid = p;
            pool.submit(() -> {
                for (int i = 0; i < perProducer; i++) {
                    DecisionEvent ev = DecisionEvent.builder()
                            .aiSystemId("drop-newest-test")
                            .correlationId("tx-newest-" + pid + "-" + i)
                            .score(100.0)
                            .build();

                    if (queue.offer(ev)) {
                        acceptedCount.incrementAndGet();
                    } else {
                        rejectedCount.incrementAndGet();
                    }
                }
                latch.countDown();
            });
        }

        latch.await(5, TimeUnit.SECONDS);
        pool.shutdownNow();

        int currentSize = queue.size();
        long enqueuedTelemetry = queue.getEnqueuedCount();
        long droppedTelemetry = queue.getDroppedCount();

        System.out.printf("    DROP_NEWEST Invariant Check:%n");
        System.out.printf("    totalSubmissions=%d, acceptedCount=%d, rejectedCount=%d%n",
                totalSubmissions, acceptedCount.get(), rejectedCount.get());
        System.out.printf("    queue.size()=%d, enqueuedTelemetry=%d, droppedTelemetry=%d%n",
                currentSize, enqueuedTelemetry, droppedTelemetry);

        if (currentSize > capacity) {
            throw new AssertionError("Queue size " + currentSize + " exceeded capacity " + capacity);
        }
        if (acceptedCount.get() + rejectedCount.get() != totalSubmissions) {
            throw new AssertionError("Total submissions mismatch: " + (acceptedCount.get() + rejectedCount.get()));
        }
        if (enqueuedTelemetry != acceptedCount.get()) {
            throw new AssertionError(String.format("enqueuedCount telemetry (%d) != acceptedCount (%d)",
                    enqueuedTelemetry, acceptedCount.get()));
        }
        if (droppedTelemetry != rejectedCount.get()) {
            throw new AssertionError(String.format("droppedCount telemetry (%d) != rejectedCount (%d)",
                    droppedTelemetry, rejectedCount.get()));
        }
        if (enqueuedTelemetry + droppedTelemetry != totalSubmissions) {
            throw new AssertionError(String.format("Conservation law violated: enqueued(%d) + dropped(%d) != total(%d)",
                    enqueuedTelemetry, droppedTelemetry, totalSubmissions));
        }

        System.out.println("  [PASS] Challenge 3A: DROP_NEWEST maintains strict bounded capacity and exact telemetry conservation.");
    }

    public void challengeQueueOverflowDropOldestOrderingAndInvariants() throws Throwable {
        System.out.println("\n[*] Challenge 3B: Bounded Queue Overflow Invariants and Ordering under DROP_OLDEST...");

        // Part 1: Deterministic FIFO Ordering Check
        {
            final int capacity = 5;
            BoundedEventQueue queue = new BoundedEventQueue(capacity, DropPolicy.DROP_OLDEST);

            for (int i = 0; i < 10; i++) {
                DecisionEvent ev = DecisionEvent.builder()
                        .aiSystemId("fifo-test")
                        .correlationId("tx-" + i)
                        .score((double) i)
                        .build();
                queue.offer(ev);
            }

            if (queue.size() != capacity) {
                throw new AssertionError("Queue size should equal capacity 5, got: " + queue.size());
            }
            if (queue.getDroppedCount() != 5) {
                throw new AssertionError("Dropped count should be 5 for 5 evicted items, got: " + queue.getDroppedCount());
            }

            for (int expected = 5; expected < 10; expected++) {
                DecisionEvent polled = queue.poll();
                if (polled == null) {
                    throw new AssertionError("Queue ran empty prematurely at item " + expected);
                }
                String expectedCorr = "tx-" + expected;
                if (!expectedCorr.equals(polled.getCorrelationId())) {
                    throw new AssertionError(String.format("FIFO violation: expected %s, got %s",
                            expectedCorr, polled.getCorrelationId()));
                }
            }

            if (queue.poll() != null) {
                throw new AssertionError("Queue should be empty after 5 polls");
            }
        }

        // Part 2: High Concurrency DROP_OLDEST Bounds & Thread-safety
        {
            final int capacity = 50;
            final int producers = 10;
            final int perProducer = 200;
            final int totalSubmissions = producers * perProducer; // 2,000

            BoundedEventQueue queue = new BoundedEventQueue(capacity, DropPolicy.DROP_OLDEST);

            ExecutorService pool = Executors.newFixedThreadPool(producers);
            CountDownLatch latch = new CountDownLatch(producers);
            AtomicInteger acceptedReturns = new AtomicInteger(0);
            AtomicInteger rejectedReturns = new AtomicInteger(0);

            for (int p = 0; p < producers; p++) {
                final int pid = p;
                pool.submit(() -> {
                    for (int i = 0; i < perProducer; i++) {
                        DecisionEvent ev = DecisionEvent.builder()
                                .aiSystemId("oldest-race-test")
                                .correlationId("tx-oldest-" + pid + "-" + i)
                                .build();

                        if (queue.offer(ev)) {
                            acceptedReturns.incrementAndGet();
                        } else {
                            rejectedReturns.incrementAndGet();
                        }
                    }
                    latch.countDown();
                });
            }

            latch.await(5, TimeUnit.SECONDS);
            pool.shutdownNow();

            int size = queue.size();
            long enqueued = queue.getEnqueuedCount();
            long dropped = queue.getDroppedCount();

            System.out.printf("    DROP_OLDEST Concurrent Metrics:%n");
            System.out.printf("    totalSubmissions=%d, acceptedReturns=%d, rejectedReturns=%d%n",
                    totalSubmissions, acceptedReturns.get(), rejectedReturns.get());
            System.out.printf("    queue.size()=%d, enqueuedCount=%d, droppedCount=%d%n",
                    size, enqueued, dropped);

            if (size > capacity) {
                throw new AssertionError("Queue size " + size + " exceeded capacity " + capacity);
            }
            if (enqueued != acceptedReturns.get()) {
                throw new AssertionError("enqueuedCount must match accepted returns");
            }
        }

        System.out.println("  [PASS] Challenge 3B: DROP_OLDEST enforces eviction of oldest elements and maintains bounded capacity.");
    }

    // =========================================================================
    // MANDATE 4: APPROVAL COMPLETABLEFUTURE TIMEOUT & TERMINAL STATE LIFECYCLE
    // =========================================================================

    public void challengeApprovalCompletableFutureTerminalStateLifecycle() throws Throwable {
        System.out.println("\n[*] Challenge 4A: CompletableFuture Terminal States (APPROVED & REJECTED 4-Eyes Lifecycle)...");

        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            AtomicInteger approveCount = new AtomicInteger(0);

            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String reqBody = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                String resp;
                if (reqBody.contains("FORCE_REJECT")) {
                    resp = "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-rej-99\",\"poll_url\":\"/api/v1/decisions/dec-rej-99/status\"}";
                } else {
                    resp = "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-appr-88\",\"poll_url\":\"/api/v1/decisions/dec-appr-88/status\"}";
                }
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            server.registerHandler("/api/v1/decisions/dec-appr-88/status", exchange -> {
                int c = approveCount.incrementAndGet();
                if (c == 1) {
                    MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"PENDING\",\"decision_id\":\"dec-appr-88\"}");
                } else if (c == 2) {
                    MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"AWAITING_SECOND_APPROVAL\",\"decision_id\":\"dec-appr-88\"}");
                } else {
                    String approved = "{"
                            + "\"status\":\"APPROVED\","
                            + "\"decision_id\":\"dec-appr-88\","
                            + "\"approvers\":[\"senior_risk_officer_1\",\"compliance_officer_2\"]"
                            + "}";
                    MockHttpServerHelper.sendResponse(exchange, 200, approved);
                }
            });

            server.registerHandler("/api/v1/decisions/dec-rej-99/status", exchange -> {
                String rej = "{"
                        + "\"status\":\"REJECTED\","
                        + "\"decision_id\":\"dec-rej-99\","
                        + "\"rejection_reason\":\"Applicant sanction list match found\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 200, rej);
            });

            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .pollIntervalMs(20)
                    .defaultApprovalTimeoutMs(2000)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent apprEvent = DecisionEvent.builder()
                        .aiSystemId("credit-lifecycle")
                        .score(900.0)
                        .correlationId("tx-appr-lifecycle")
                        .build();

                CompletableFuture<ApprovalResult> futureAppr = client.requestApprovalAsync(apprEvent);
                ApprovalResult resultAppr = futureAppr.get(3, TimeUnit.SECONDS);

                if (!resultAppr.isApproved()) {
                    throw new AssertionError("Expected isApproved() == true");
                }
                if (resultAppr.getStatus() != ApprovalStatus.APPROVED) {
                    throw new AssertionError("Status must be APPROVED, got: " + resultAppr.getStatus());
                }
                if (!"dec-appr-88".equals(resultAppr.getDecisionId())) {
                    throw new AssertionError("Decision ID mismatch: " + resultAppr.getDecisionId());
                }
                if (resultAppr.getApprovers().size() != 2) {
                    throw new AssertionError("4-Eyes requirement failed: approvers count was " + resultAppr.getApprovers().size());
                }

                DecisionEvent rejEvent = DecisionEvent.builder()
                        .aiSystemId("credit-lifecycle")
                        .decision("FORCE_REJECT")
                        .score(200.0)
                        .correlationId("tx-rej-lifecycle")
                        .build();

                CompletableFuture<ApprovalResult> futureRej = client.requestApprovalAsync(rejEvent);
                ApprovalResult resultRej = futureRej.get(3, TimeUnit.SECONDS);

                if (resultRej.isApproved()) {
                    throw new AssertionError("Expected isApproved() == false on rejection");
                }
                if (resultRej.getStatus() != ApprovalStatus.REJECTED) {
                    throw new AssertionError("Status must be REJECTED, got: " + resultRej.getStatus());
                }
                if (!resultRej.getRejectionReason().contains("sanction list match")) {
                    throw new AssertionError("Rejection reason mismatch: " + resultRej.getRejectionReason());
                }

                System.out.println("  [PASS] Challenge 4A: CompletableFuture resolves correctly for APPROVED and REJECTED states.");
            }
        }
    }

    public void challengeApprovalCompletableFutureTimeoutAndExceptionLifecycle() throws Throwable {
        System.out.println("\n[*] Challenge 4B: CompletableFuture Timeout & Lifecycle Probe against Slow Mock Server...");

        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            AtomicInteger pollRequestsReceived = new AtomicInteger(0);

            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String resp = "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-stalled-01\",\"poll_url\":\"/api/v1/decisions/dec-stalled-01/status\"}";
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            server.registerHandler("/api/v1/decisions/dec-stalled-01/status", exchange -> {
                pollRequestsReceived.incrementAndGet();
                MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-stalled-01\"}");
            });

            server.start();

            final long shortTimeoutMs = 200;
            final long pollIntervalMs = 25;

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .pollIntervalMs(pollIntervalMs)
                    .defaultApprovalTimeoutMs(shortTimeoutMs)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("slow-mock-system")
                        .score(700.0)
                        .correlationId("tx-timeout-probe")
                        .build();

                long start = System.currentTimeMillis();
                CompletableFuture<ApprovalResult> future = client.requestApprovalAsync(
                        event,
                        Duration.ofMillis(shortTimeoutMs),
                        Duration.ofMillis(pollIntervalMs)
                );

                ApprovalResult result = future.get(1, TimeUnit.SECONDS);
                long elapsed = System.currentTimeMillis() - start;

                System.out.printf("    requestApprovalAsync completed in %dms (configured timeout=%dms)%n",
                        elapsed, shortTimeoutMs);
                System.out.printf("    Returned status: %s, isTerminal: %b, isApproved: %b%n",
                        result.getStatus(), result.isTerminal(), result.isApproved());

                if (result.getStatus() != ApprovalStatus.EXPIRED) {
                    throw new AssertionError("Expected status EXPIRED on polling timeout, got: " + result.getStatus());
                }
                if (!result.isTerminal()) {
                    throw new AssertionError("EXPIRED must be recognized as terminal status");
                }
                if (result.isApproved()) {
                    throw new AssertionError("Expired decision must not be approved");
                }

                int pollsAtTimeout = pollRequestsReceived.get();
                Thread.sleep(100);
                int pollsAfterWait = pollRequestsReceived.get();

                System.out.printf("    Poll requests: at timeout=%d, after +100ms idle=%d%n",
                        pollsAtTimeout, pollsAfterWait);

                if (pollsAfterWait > pollsAtTimeout + 1) {
                    throw new AssertionError(String.format(
                            "ZOMBIE POLLER LEAK: Poller continued querying server after future completed (%d -> %d)",
                            pollsAtTimeout, pollsAfterWait));
                }

                System.out.println("    [NOTE] Investigating ApprovalTimeoutException lifecycle:");
                System.out.println("    - ApprovalTimeoutException class is defined under com.aievidence.sdk.exceptions.");
                System.out.println("    - SDK requestApprovalAsync() resolves timeout by returning ApprovalResult with status=EXPIRED");
                System.out.println("      (preserving fault isolation and preventing unhandled ExecutionException in reactive pipelines).");

                System.out.println("  [PASS] Challenge 4B: CompletableFuture terminates cleanly on timeout and cancels background poller without leaks.");
            }
        }
    }
}
