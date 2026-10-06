package com.aievidence.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Background daemon worker responsible for micro-batching and dispatching queued decision events
 * to the Ingest API via standard java.net.http.HttpClient.
 */
public class DeliveryWorker implements Runnable {

    private final BoundedEventQueue eventQueue;
    private final ClientConfig config;
    private final HttpClient httpClient;
    private final Thread workerThread;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final java.util.concurrent.atomic.AtomicInteger inFlight = new java.util.concurrent.atomic.AtomicInteger(0);
    private final Object signal = new Object();

    public DeliveryWorker(BoundedEventQueue eventQueue, ClientConfig config, HttpClient httpClient) {
        this.eventQueue = eventQueue;
        this.config = config;
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(config.getHttpTimeoutMs()))
                .build();

        this.workerThread = new Thread(this, "aievidence-delivery-worker");
        this.workerThread.setDaemon(true);
        this.workerThread.start();
    }

    @Override
    public void run() {
        while (running.get()) {
            try {
                drainAndSend(config.getMaxBatchSize());

                // Sleep for flush interval or until signaled
                synchronized (signal) {
                    if (eventQueue.isEmpty() && running.get()) {
                        signal.wait(config.getFlushIntervalMs());
                    }
                }
            } catch (InterruptedException e) {
                if (!running.get()) {
                    break;
                }
                Thread.currentThread().interrupt();
            } catch (Throwable t) {
                // Enterprise Fault Isolation: Never crash worker thread
            }
        }
    }

    /**
     * Wakes up worker thread to process queued events immediately.
     */
    public void trigger() {
        synchronized (signal) {
            signal.notifyAll();
        }
    }

    /**
     * Drains up to maxBatchSize events and sends them via HTTP POST.
     */
    public int drainAndSend(int maxBatchSize) {
        List<DecisionEvent> batch = new ArrayList<>(maxBatchSize);
        int drained = eventQueue.drainTo(batch, maxBatchSize);
        if (drained == 0) {
            DecisionEvent single = eventQueue.poll();
            if (single != null) {
                batch.add(single);
                drained = 1;
            }
        }

        if (drained > 0) {
            inFlight.addAndGet(drained);
            try {
                for (DecisionEvent event : batch) {
                    sendSingleEvent(event);
                }
            } finally {
                inFlight.addAndGet(-drained);
            }
        }
        return drained;
    }

    /**
     * Dispatches a single event over HTTP.
     * Absorbs all network and HTTP errors to preserve zero-exception caller guarantees.
     */
    public boolean sendSingleEvent(DecisionEvent event) {
        if (event == null) {
            return false;
        }
        try {
            String json = JsonUtil.toJson(event);
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(config.getIngestUrl()))
                    .timeout(Duration.ofMillis(config.getHttpTimeoutMs()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));

            String aiSystemId = event.getAiSystemId() != null ? event.getAiSystemId() : config.getAiSystemId();
            if (aiSystemId != null) {
                reqBuilder.header("X-AI-System-ID", aiSystemId);
            }
            if (event.getCorrelationId() != null) {
                reqBuilder.header("X-Correlation-ID", event.getCorrelationId());
            }

            HttpResponse<String> response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
            int sc = response.statusCode();
            if (sc == 200 || sc == 202) {
                eventQueue.incrementDelivered(1);
                return true;
            }
            return false;
        } catch (IOException | InterruptedException e) {
            // Fault isolation: Network error suppressed
            return false;
        } catch (Throwable t) {
            // Fault isolation: Any error suppressed
            return false;
        }
    }

    /**
     * Synchronously flushes remaining items in the queue up to timeout.
     */
    public boolean flush(Duration timeout) {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while ((!eventQueue.isEmpty() || inFlight.get() > 0) && System.currentTimeMillis() < deadline) {
            drainAndSend(config.getMaxBatchSize());
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return eventQueue.isEmpty() && inFlight.get() == 0;
    }

    /**
     * Shuts down the background worker.
     */
    public void shutdown(Duration timeout) {
        running.set(false);
        trigger();
        flush(timeout);
        try {
            workerThread.join(Math.min(timeout.toMillis(), 1000));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
