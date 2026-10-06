package com.aievidence.sdk;

import java.util.Arrays;
import java.util.Map;

/**
 * Latency SLA Verification Test: Asserts that every logDecision() call executes
 * in strictly < 5.0ms SLA across 1,000 consecutive calls under realistic workloads.
 */
public class LatencySlaTest {

    public static void main(String[] args) throws Exception {
        new LatencySlaTest().runAll();
    }

    public void runAll() throws Exception {
        testLogDecisionLatencySla();
        System.out.println("  [PASS] LatencySlaTest: All tests passed.");
    }

    public void testLogDecisionLatencySla() {
        ClientConfig config = ClientConfig.builder()
                .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                .aiSystemId("credit-risk-sla")
                .queueCapacity(50_000)
                .build();

        try (EvidenceClient client = EvidenceClient.create(config)) {
            DecisionEvent sampleEvent = DecisionEvent.builder()
                    .aiSystemId("credit-risk-sla")
                    .modelVersion("v3.0.0")
                    .score(780.0)
                    .decision("APPROVE")
                    .features(Map.of(
                            "income", 35000000L,
                            "debt_ratio", 0.15,
                            "credit_history_months", 48,
                            "delinquencies_2yrs", 0
                    ))
                    .correlationId("tx-sla-000")
                    .build();

            // Warm-up JIT compiler
            for (int i = 0; i < 200; i++) {
                client.logDecision(sampleEvent);
            }

            // Benchmark 1,000 iterations
            final int iterations = 1000;
            long[] durationsNs = new long[iterations];
            long maxAllowedNs = 5_000_000L; // 5.0ms SLA in nanoseconds

            for (int i = 0; i < iterations; i++) {
                long start = System.nanoTime();
                boolean result = client.logDecision(sampleEvent);
                long elapsed = System.nanoTime() - start;
                durationsNs[i] = elapsed;

                assert result : "Event must be accepted by bounded buffer";
                assert elapsed < maxAllowedNs : "SLA VIOLATION: logDecision took " + (elapsed / 1_000_000.0) + "ms, exceeding 5.0ms SLA limit";
            }

            Arrays.sort(durationsNs);
            double minMs = durationsNs[0] / 1_000_000.0;
            double p50Ms = durationsNs[(int) (iterations * 0.50)] / 1_000_000.0;
            double p95Ms = durationsNs[(int) (iterations * 0.95)] / 1_000_000.0;
            double p99Ms = durationsNs[(int) (iterations * 0.99)] / 1_000_000.0;
            double maxMs = durationsNs[iterations - 1] / 1_000_000.0;

            System.out.printf("    Latency SLA Metrics (1,000 calls): min=%.4fms, p50=%.4fms, p95=%.4fms, p99=%.4fms, max=%.4fms%n",
                    minMs, p50Ms, p95Ms, p99Ms, maxMs);

            assert maxMs < 5.0 : "Max latency must be strictly less than 5.0ms";
        }
    }
}
