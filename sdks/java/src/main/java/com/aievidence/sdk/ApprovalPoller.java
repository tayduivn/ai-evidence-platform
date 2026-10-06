package com.aievidence.sdk;

import com.aievidence.sdk.exceptions.ApprovalTimeoutException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Scheduled polling worker that queries /api/v1/decisions/{id}/status until
 * terminal approval state (APPROVED, REJECTED, EXPIRED) is reached or timeout occurs.
 */
public class ApprovalPoller implements AutoCloseable {

    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;
    private final String baseUrl;

    public ApprovalPoller(HttpClient httpClient, String baseUrl) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl != null ? baseUrl : "http://localhost:8081";
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "aievidence-approval-poller");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Polls status URL asynchronously returning a CompletableFuture that resolves
     * when the decision is APPROVED, REJECTED, or EXPIRED.
     */
    public CompletableFuture<ApprovalResult> pollStatus(
            String pollUrl,
            String decisionId,
            String correlationId,
            Duration timeout,
            Duration interval) {

        CompletableFuture<ApprovalResult> future = new CompletableFuture<>();
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        long intervalMs = interval != null ? interval.toMillis() : 500;
        String resolvedUrl = resolveUrl(pollUrl);

        AtomicBoolean completed = new AtomicBoolean(false);

        ScheduledFuture<?>[] scheduledHolder = new ScheduledFuture<?>[1];
        scheduledHolder[0] = scheduler.scheduleWithFixedDelay(() -> {
            if (completed.get() || future.isDone()) {
                if (scheduledHolder[0] != null) scheduledHolder[0].cancel(false);
                return;
            }

            if (System.currentTimeMillis() >= deadline) {
                if (completed.compareAndSet(false, true)) {
                    if (scheduledHolder[0] != null) scheduledHolder[0].cancel(false);
                    future.complete(ApprovalResult.expired(decisionId, correlationId));
                }
                return;
            }

            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(resolvedUrl))
                        .timeout(Duration.ofSeconds(3))
                        .GET()
                        .build();

                httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                        .thenAccept(resp -> {
                            if (resp.statusCode() == 200) {
                                Map<String, Object> map = JsonUtil.parseJsonObject(resp.body());
                                String statusStr = (String) map.get("status");
                                ApprovalStatus status = ApprovalStatus.fromString(statusStr);

                                if (status.isTerminal()) {
                                    if (completed.compareAndSet(false, true)) {
                                        if (scheduledHolder[0] != null) scheduledHolder[0].cancel(false);

                                        List<String> approvers = parseApprovers(map.get("approvers"));
                                        String reason = (String) map.get("rejection_reason");

                                        if (status == ApprovalStatus.APPROVED) {
                                            future.complete(ApprovalResult.approved(decisionId, correlationId, approvers));
                                        } else if (status == ApprovalStatus.REJECTED) {
                                            future.complete(ApprovalResult.rejected(decisionId, correlationId, reason));
                                        } else {
                                            future.complete(ApprovalResult.expired(decisionId, correlationId));
                                        }
                                    }
                                }
                            }
                        })
                        .exceptionally(ex -> null); // keep retrying on network errors until timeout
            } catch (Throwable t) {
                // keep retrying
            }
        }, 0, intervalMs, TimeUnit.MILLISECONDS);

        // Cancel scheduled task if caller cancels the future
        future.whenComplete((r, ex) -> {
            if (scheduledHolder[0] != null) {
                scheduledHolder[0].cancel(false);
            }
        });

        return future;
    }

    private String resolveUrl(String pollUrl) {
        if (pollUrl == null || pollUrl.isBlank()) {
            return baseUrl;
        }
        if (pollUrl.startsWith("http://") || pollUrl.startsWith("https://")) {
            return pollUrl;
        }
        // Build absolute URL from baseUrl
        try {
            URI base = URI.create(baseUrl);
            String scheme = base.getScheme() != null ? base.getScheme() : "http";
            String host = base.getHost() != null ? base.getHost() : "localhost";
            int port = base.getPort();
            String authority = port > 0 ? host + ":" + port : host;
            String path = pollUrl.startsWith("/") ? pollUrl : "/" + pollUrl;
            return scheme + "://" + authority + path;
        } catch (Exception e) {
            return pollUrl;
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> parseApprovers(Object obj) {
        List<String> result = new ArrayList<>();
        if (obj instanceof Iterable) {
            for (Object item : (Iterable<?>) obj) {
                if (item != null) {
                    result.add(String.valueOf(item));
                }
            }
        }
        return result;
    }

    @Override
    public void close() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
