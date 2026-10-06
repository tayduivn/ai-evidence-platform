package com.aievidence.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Enterprise client facade for AI Evidence & Accountability Platform.
 * Provides strictly non-blocking decision logging (< 5.0ms SLA) with local bounded buffering,
 * micro-batching background delivery, and asynchronous human-in-the-loop approval workflows.
 */
public class EvidenceClient implements AutoCloseable {

    private final ClientConfig config;
    private final BoundedEventQueue eventQueue;
    private final HttpClient httpClient;
    private final DeliveryWorker deliveryWorker;
    private final ApprovalPoller approvalPoller;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public EvidenceClient(ClientConfig config) {
        this(config, null);
    }

    public EvidenceClient(ClientConfig config, HttpClient customHttpClient) {
        this.config = Objects.requireNonNull(config, "ClientConfig must not be null");
        this.eventQueue = new BoundedEventQueue(config.getQueueCapacity(), config.getDropPolicy());

        this.httpClient = customHttpClient != null ? customHttpClient : HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(config.getHttpTimeoutMs()))
                .build();

        this.deliveryWorker = new DeliveryWorker(this.eventQueue, this.config, this.httpClient);
        this.approvalPoller = new ApprovalPoller(this.httpClient, this.config.getIngestUrl());
    }

    /**
     * Factory method to create a new EvidenceClient with given configuration.
     */
    public static EvidenceClient create(ClientConfig config) {
        return new EvidenceClient(config);
    }

    /**
     * Convenience builder starting from ClientConfig.
     */
    public static ClientConfig.Builder builder() {
        return ClientConfig.builder();
    }

    /**
     * Non-blocking decision logging satisfying the strict < 5.0ms SLA.
     * Enqueues the event into an in-memory bounded ring buffer in < 0.05ms without
     * performing network I/O on the calling thread.
     * Guaranteed never to throw unhandled runtime exceptions to the caller.
     *
     * @param event DecisionEvent to record
     * @return true if accepted into the buffer; false if dropped or client closed
     */
    public boolean logDecision(DecisionEvent event) {
        if (closed.get() || event == null) {
            return false;
        }
        try {
            boolean accepted = eventQueue.offer(event);
            if (accepted) {
                deliveryWorker.trigger();
            }
            return accepted;
        } catch (Throwable t) {
            // Enterprise fault isolation: never leak exceptions to the caller
            return false;
        }
    }

    /**
     * Asynchronous non-blocking decision logging returning a CompletableFuture.
     *
     * @param event DecisionEvent to record
     * @return CompletableFuture completing with true if enqueued, false otherwise
     */
    public CompletableFuture<Boolean> logDecisionAsync(DecisionEvent event) {
        try {
            boolean result = logDecision(event);
            return CompletableFuture.completedFuture(result);
        } catch (Throwable t) {
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Dispatches a human-in-the-loop approval request and polls asynchronously until resolved.
     *
     * @param event DecisionEvent requiring human review
     * @return CompletableFuture resolving to ApprovalResult
     */
    public CompletableFuture<ApprovalResult> requestApprovalAsync(DecisionEvent event) {
        return requestApprovalAsync(
                event,
                Duration.ofMillis(config.getDefaultApprovalTimeoutMs()),
                Duration.ofMillis(config.getPollIntervalMs())
        );
    }

    /**
     * Dispatches a human-in-the-loop approval request with custom timeout and polling interval.
     */
    public CompletableFuture<ApprovalResult> requestApprovalAsync(
            DecisionEvent event,
            Duration timeout,
            Duration pollInterval) {

        if (closed.get()) {
            CompletableFuture<ApprovalResult> failed = new CompletableFuture<>();
            failed.complete(ApprovalResult.rejected(null, event != null ? event.getCorrelationId() : null, "Client is closed"));
            return failed;
        }

        if (event == null) {
            CompletableFuture<ApprovalResult> failed = new CompletableFuture<>();
            failed.complete(ApprovalResult.rejected(null, null, "DecisionEvent must not be null"));
            return failed;
        }

        // Force requiresApproval = true
        DecisionEvent approvalEvent = event.withRequiresApproval(true);
        String json = JsonUtil.toJson(approvalEvent);

        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(config.getIngestUrl()))
                .timeout(Duration.ofMillis(config.getHttpTimeoutMs()))
                .header("Content-Type", "application/json")
                .header("X-Require-Approval", "true")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));

        String aiSystemId = approvalEvent.getAiSystemId() != null ? approvalEvent.getAiSystemId() : config.getAiSystemId();
        if (aiSystemId != null) {
            reqBuilder.header("X-AI-System-ID", aiSystemId);
        }
        if (approvalEvent.getCorrelationId() != null) {
            reqBuilder.header("X-Correlation-ID", approvalEvent.getCorrelationId());
        }

        return httpClient.sendAsync(reqBuilder.build(), HttpResponse.BodyHandlers.ofString())
                .thenCompose(response -> {
                    int sc = response.statusCode();
                    Map<String, Object> bodyMap = JsonUtil.parseJsonObject(response.body());

                    String corrId = approvalEvent.getCorrelationId();
                    if (bodyMap.containsKey("correlation_id")) {
                        corrId = String.valueOf(bodyMap.get("correlation_id"));
                    }

                    if (sc == 202) { // Accepted & Pending Approval
                        String decisionId = (String) bodyMap.get("decision_id");
                        String pollUrl = (String) bodyMap.get("poll_url");

                        if (pollUrl != null && !pollUrl.isBlank()) {
                            return approvalPoller.pollStatus(pollUrl, decisionId, corrId, timeout, pollInterval);
                        } else {
                            return CompletableFuture.completedFuture(ApprovalResult.pending(decisionId, corrId, null));
                        }
                    } else if (sc == 200) { // Auto-approved or Ingested
                        return CompletableFuture.completedFuture(ApprovalResult.approved("dec-" + corrId, corrId, null));
                    } else {
                        String errMsg = bodyMap.containsKey("error") ? String.valueOf(bodyMap.get("error")) : "HTTP " + sc;
                        return CompletableFuture.completedFuture(ApprovalResult.rejected(null, corrId, errMsg));
                    }
                })
                .exceptionally(ex -> ApprovalResult.rejected(null, approvalEvent.getCorrelationId(), ex.getMessage()));
    }

    /**
     * Synchronous blocking convenience method for approval workflow.
     *
     * @param event DecisionEvent requiring human review
     * @param timeout Maximum duration to wait before timing out
     * @return ApprovalResult
     */
    public ApprovalResult requestApproval(DecisionEvent event, Duration timeout) {
        try {
            return requestApprovalAsync(event, timeout, Duration.ofMillis(config.getPollIntervalMs()))
                    .get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            return ApprovalResult.expired(null, event != null ? event.getCorrelationId() : null);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return ApprovalResult.rejected(null, event != null ? event.getCorrelationId() : null, cause.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ApprovalResult.rejected(null, event != null ? event.getCorrelationId() : null, "Interrupted");
        }
    }

    /**
     * Synchronously flushes all pending events in the queue up to timeout.
     */
    public boolean flush(Duration timeout) {
        return deliveryWorker.flush(timeout);
    }

    public long getEnqueuedCount() {
        return eventQueue.getEnqueuedCount();
    }

    public long getDroppedCount() {
        return eventQueue.getDroppedCount();
    }

    public long getDeliveredCount() {
        return eventQueue.getDeliveredCount();
    }

    public int getQueueSize() {
        return eventQueue.size();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            deliveryWorker.shutdown(Duration.ofSeconds(2));
            approvalPoller.close();
        }
    }
}
