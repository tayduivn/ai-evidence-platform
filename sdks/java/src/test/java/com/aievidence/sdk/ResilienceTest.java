package com.aievidence.sdk;

import java.io.IOException;
import java.time.Duration;

/**
 * Resilience & Fault Isolation Tests:
 * Proves that network degradation, dead endpoints, or slow HTTP servers
 * never leak unhandled exceptions or block the primary calling thread.
 */
public class ResilienceTest {

    public static void main(String[] args) throws Exception {
        new ResilienceTest().runAll();
    }

    public void runAll() throws Exception {
        testOfflineEndpointZeroExceptions();
        testSlowServerCallerIsolation();
        testHttp500ServerHandling();
        System.out.println("  [PASS] ResilienceTest: All tests passed.");
    }

    public void testOfflineEndpointZeroExceptions() {
        // Unreachable endpoint
        ClientConfig config = ClientConfig.builder()
                .ingestUrl("http://127.0.0.1:59999/api/v1/ml/ingest")
                .aiSystemId("credit-offline-test")
                .queueCapacity(100)
                .flushIntervalMs(20)
                .httpTimeoutMs(200)
                .build();

        try (EvidenceClient client = EvidenceClient.create(config)) {
            DecisionEvent event = DecisionEvent.builder()
                    .aiSystemId("credit-offline-test")
                    .score(500.0)
                    .correlationId("tx-offline-01")
                    .build();

            // Must never throw ConnectException or any exception
            for (int i = 0; i < 20; i++) {
                boolean accepted = client.logDecision(event);
                assert accepted : "Event should still be safely accepted into local buffer";
            }

            // Flush attempt against dead server must terminate cleanly without throwing
            client.flush(Duration.ofMillis(150));
        } catch (Throwable t) {
            throw new AssertionError("Zero Exception Violation: offline endpoint threw " + t.getClass().getName(), t);
        }
    }

    public void testSlowServerCallerIsolation() throws IOException {
        try (MockHttpServerHelper slowServer = new MockHttpServerHelper()) {
            // Server delays response by 2,000ms
            slowServer.registerHandler("/api/v1/ml/ingest", exchange -> {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ignored) {}
                MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"INGESTED\"}");
            });
            slowServer.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(slowServer.getBaseUrl() + "/api/v1/ml/ingest")
                    .aiSystemId("slow-server-test")
                    .queueCapacity(1000)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("slow-server-test")
                        .score(650.0)
                        .correlationId("tx-slow-01")
                        .build();

                long start = System.nanoTime();
                boolean accepted = client.logDecision(event);
                long elapsed = System.nanoTime() - start;

                assert accepted : "Event must be accepted";
                assert elapsed < 5_000_000L : "Slow downstream must not delay calling thread (took " + (elapsed / 1_000_000.0) + "ms)";
            }
        }
    }

    public void testHttp500ServerHandling() throws IOException {
        try (MockHttpServerHelper errorServer = new MockHttpServerHelper()) {
            errorServer.registerHandler("/api/v1/ml/ingest", exchange -> {
                MockHttpServerHelper.sendResponse(exchange, 500, "{\"error\":\"Internal database failure\"}");
            });
            errorServer.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(errorServer.getBaseUrl() + "/api/v1/ml/ingest")
                    .aiSystemId("error-500-test")
                    .queueCapacity(100)
                    .flushIntervalMs(20)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("error-500-test")
                        .score(700.0)
                        .correlationId("tx-err-01")
                        .build();

                boolean accepted = client.logDecision(event);
                assert accepted : "Event must be accepted";

                client.flush(Duration.ofMillis(100));
            } catch (Throwable t) {
                throw new AssertionError("Zero Exception Violation: HTTP 500 threw " + t.getClass().getName(), t);
            }
        }
    }
}
