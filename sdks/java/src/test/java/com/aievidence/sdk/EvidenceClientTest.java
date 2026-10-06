package com.aievidence.sdk;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Functional unit tests for EvidenceClient.
 */
public class EvidenceClientTest {

    public static void main(String[] args) throws Exception {
        new EvidenceClientTest().runAll();
    }

    public void runAll() throws Exception {
        testClientConfiguration();
        testBasicLogDecisionAndDelivery();
        testLogDecisionAsync();
        testClientCloseRejection();
        System.out.println("  [PASS] EvidenceClientTest: All tests passed.");
    }

    public void testClientConfiguration() {
        ClientConfig config = ClientConfig.builder()
                .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                .aiSystemId("credit-scoring-v1")
                .artifactHash("abc123hash")
                .queueCapacity(5000)
                .maxBatchSize(20)
                .flushIntervalMs(30)
                .dropPolicy(DropPolicy.DROP_OLDEST)
                .build();

        assert "http://localhost:8081/api/v1/ml/ingest".equals(config.getIngestUrl()) : "IngestUrl mismatch";
        assert "credit-scoring-v1".equals(config.getAiSystemId()) : "AiSystemId mismatch";
        assert config.getQueueCapacity() == 5000 : "QueueCapacity mismatch";
        assert config.getMaxBatchSize() == 20 : "MaxBatchSize mismatch";
        assert config.getFlushIntervalMs() == 30 : "FlushInterval mismatch";
        assert config.getDropPolicy() == DropPolicy.DROP_OLDEST : "DropPolicy mismatch";
    }

    public void testBasicLogDecisionAndDelivery() throws IOException {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            AtomicInteger received = new AtomicInteger(0);
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                received.incrementAndGet();
                MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"INGESTED\",\"event_id\":\"ev-01\"}");
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .aiSystemId("fraud-detection")
                    .queueCapacity(100)
                    .flushIntervalMs(20)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("fraud-detection")
                        .score(0.85)
                        .decision("BLOCK_TRANSACTION")
                        .features(Map.of("amount", 5000000L, "card_country", "VN"))
                        .correlationId("tx-test-01")
                        .build();

                boolean enqueued = client.logDecision(event);
                assert enqueued : "Event should be enqueued";
                assert client.getEnqueuedCount() == 1 : "Enqueued count should be 1";

                boolean flushed = client.flush(Duration.ofSeconds(2));
                assert flushed : "Flush should succeed";
                assert received.get() >= 1 : "Server should have received the event";
                assert client.getDeliveredCount() >= 1 : "Delivered count should be at least 1";
            }
        }
    }

    public void testLogDecisionAsync() throws Exception {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"INGESTED\"}");
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .aiSystemId("async-test")
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("async-test")
                        .score(100.0)
                        .correlationId("tx-async-01")
                        .build();

                Boolean result = client.logDecisionAsync(event).get();
                assert Boolean.TRUE.equals(result) : "Async result should be true";
            }
        }
    }

    public void testClientCloseRejection() {
        ClientConfig config = ClientConfig.builder()
                .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
                .build();

        EvidenceClient client = EvidenceClient.create(config);
        client.close();

        DecisionEvent event = DecisionEvent.builder()
                .aiSystemId("closed-test")
                .score(1.0)
                .build();

        boolean accepted = client.logDecision(event);
        assert !accepted : "Closed client must reject logDecision";
    }
}
