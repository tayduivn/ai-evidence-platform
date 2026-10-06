package com.aievidence.sdk;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Human-in-the-Loop Approval Workflow Tests:
 * Verifies asynchronous and synchronous approval requests, status polling,
 * 4-eyes approval verification, rejection, and timeout expiration.
 */
public class ApprovalWorkflowTest {

    public static void main(String[] args) throws Exception {
        new ApprovalWorkflowTest().runAll();
    }

    public void runAll() throws Exception {
        testAsyncApprovalFlow();
        testSyncApprovalFlow();
        testRejectionFlow();
        testTimeoutExpirationFlow();
        System.out.println("  [PASS] ApprovalWorkflowTest: All tests passed.");
    }

    public void testAsyncApprovalFlow() throws Exception {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            AtomicInteger pollCount = new AtomicInteger(0);

            // Handler for POST /api/v1/ml/ingest
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String resp = "{"
                        + "\"status\":\"PENDING_APPROVAL\","
                        + "\"decision_id\":\"dec-ml-8821\","
                        + "\"correlation_id\":\"tx-appr-01\","
                        + "\"poll_url\":\"/api/v1/decisions/dec-ml-8821/status\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            // Handler for GET /api/v1/decisions/dec-ml-8821/status
            server.registerHandler("/api/v1/decisions/dec-ml-8821/status", exchange -> {
                int count = pollCount.incrementAndGet();
                if (count == 1) {
                    MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-ml-8821\"}");
                } else {
                    String approvedResp = "{"
                            + "\"status\":\"APPROVED\","
                            + "\"decision_id\":\"dec-ml-8821\","
                            + "\"approvers\":[\"senior_underwriter_01\",\"risk_director_02\"]"
                            + "}";
                    MockHttpServerHelper.sendResponse(exchange, 200, approvedResp);
                }
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .aiSystemId("credit-approval")
                    .pollIntervalMs(50)
                    .defaultApprovalTimeoutMs(3000)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("credit-approval")
                        .score(910.0)
                        .decision("LARGE_LOAN_DISBURSEMENT")
                        .features(Map.of("amount", 2000000000L))
                        .requiresApproval(true)
                        .creatorId("officer_anna")
                        .correlationId("tx-appr-01")
                        .build();

                CompletableFuture<ApprovalResult> future = client.requestApprovalAsync(event);
                ApprovalResult result = future.get();

                assert result.isApproved() : "Result must be approved";
                assert result.getStatus() == ApprovalStatus.APPROVED : "Status must be APPROVED";
                assert "dec-ml-8821".equals(result.getDecisionId()) : "DecisionId mismatch: " + result.getDecisionId();
                List<String> approvers = result.getApprovers();
                assert approvers.size() == 2 : "Must have 2 approvers (4-eyes enforcement)";
                assert approvers.contains("senior_underwriter_01") : "Missing senior_underwriter_01";
                assert approvers.contains("risk_director_02") : "Missing risk_director_02";
            }
        }
    }

    public void testSyncApprovalFlow() throws Exception {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String resp = "{"
                        + "\"status\":\"PENDING_APPROVAL\","
                        + "\"decision_id\":\"dec-sync-01\","
                        + "\"poll_url\":\"/api/v1/decisions/dec-sync-01/status\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            server.registerHandler("/api/v1/decisions/dec-sync-01/status", exchange -> {
                String approvedResp = "{"
                        + "\"status\":\"APPROVED\","
                        + "\"decision_id\":\"dec-sync-01\","
                        + "\"approvers\":[\"mgr_john\"]"
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 200, approvedResp);
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .pollIntervalMs(30)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("sync-test")
                        .score(800.0)
                        .correlationId("tx-sync-01")
                        .build();

                ApprovalResult result = client.requestApproval(event, Duration.ofSeconds(2));
                assert result.isApproved() : "Sync request must be approved";
                assert "dec-sync-01".equals(result.getDecisionId());
            }
        }
    }

    public void testRejectionFlow() throws Exception {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String resp = "{"
                        + "\"status\":\"PENDING_APPROVAL\","
                        + "\"decision_id\":\"dec-rej-01\","
                        + "\"poll_url\":\"/api/v1/decisions/dec-rej-01/status\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            server.registerHandler("/api/v1/decisions/dec-rej-01/status", exchange -> {
                String rejResp = "{"
                        + "\"status\":\"REJECTED\","
                        + "\"decision_id\":\"dec-rej-01\","
                        + "\"rejection_reason\":\"Debt service coverage ratio below policy minimum\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 200, rejResp);
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .pollIntervalMs(30)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("credit-rejection")
                        .score(450.0)
                        .correlationId("tx-rej-01")
                        .build();

                ApprovalResult result = client.requestApproval(event, Duration.ofSeconds(2));
                assert result.getStatus() == ApprovalStatus.REJECTED : "Status must be REJECTED";
                assert !result.isApproved() : "Must not be approved";
                assert result.getRejectionReason().contains("Debt service coverage ratio") : "Reason mismatch: " + result.getRejectionReason();
            }
        }
    }

    public void testTimeoutExpirationFlow() throws Exception {
        try (MockHttpServerHelper server = new MockHttpServerHelper()) {
            server.registerHandler("/api/v1/ml/ingest", exchange -> {
                String resp = "{"
                        + "\"status\":\"PENDING_APPROVAL\","
                        + "\"decision_id\":\"dec-timeout-01\","
                        + "\"poll_url\":\"/api/v1/decisions/dec-timeout-01/status\""
                        + "}";
                MockHttpServerHelper.sendResponse(exchange, 202, resp);
            });

            // Server continuously responds PENDING_APPROVAL
            server.registerHandler("/api/v1/decisions/dec-timeout-01/status", exchange -> {
                MockHttpServerHelper.sendResponse(exchange, 200, "{\"status\":\"PENDING_APPROVAL\",\"decision_id\":\"dec-timeout-01\"}");
            });
            server.start();

            ClientConfig config = ClientConfig.builder()
                    .ingestUrl(server.getBaseUrl() + "/api/v1/ml/ingest")
                    .pollIntervalMs(20)
                    .defaultApprovalTimeoutMs(150)
                    .build();

            try (EvidenceClient client = EvidenceClient.create(config)) {
                DecisionEvent event = DecisionEvent.builder()
                        .aiSystemId("timeout-test")
                        .score(700.0)
                        .correlationId("tx-to-01")
                        .build();

                ApprovalResult result = client.requestApproval(event, Duration.ofMillis(150));
                assert result.getStatus() == ApprovalStatus.EXPIRED : "Expected EXPIRED status on timeout, got: " + result.getStatus();
            }
        }
    }
}
