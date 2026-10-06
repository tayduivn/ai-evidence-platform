package com.aievidence.sdk;

import java.util.Objects;

/**
 * Configuration options for EvidenceClient.
 */
public class ClientConfig {

    private final String ingestUrl;
    private final String aiSystemId;
    private final String artifactHash;
    private final int queueCapacity;
    private final int maxBatchSize;
    private final long flushIntervalMs;
    private final long httpTimeoutMs;
    private final long pollIntervalMs;
    private final long defaultApprovalTimeoutMs;
    private final DropPolicy dropPolicy;

    private ClientConfig(Builder builder) {
        this.ingestUrl = Objects.requireNonNull(builder.ingestUrl, "ingestUrl must not be null");
        this.aiSystemId = builder.aiSystemId;
        this.artifactHash = builder.artifactHash;
        this.queueCapacity = builder.queueCapacity > 0 ? builder.queueCapacity : 10_000;
        this.maxBatchSize = builder.maxBatchSize > 0 ? builder.maxBatchSize : 50;
        this.flushIntervalMs = builder.flushIntervalMs > 0 ? builder.flushIntervalMs : 50;
        this.httpTimeoutMs = builder.httpTimeoutMs > 0 ? builder.httpTimeoutMs : 3_000;
        this.pollIntervalMs = builder.pollIntervalMs > 0 ? builder.pollIntervalMs : 500;
        this.defaultApprovalTimeoutMs = builder.defaultApprovalTimeoutMs > 0 ? builder.defaultApprovalTimeoutMs : 30_000;
        this.dropPolicy = builder.dropPolicy != null ? builder.dropPolicy : DropPolicy.DROP_NEWEST;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getIngestUrl() {
        return ingestUrl;
    }

    public String getAiSystemId() {
        return aiSystemId;
    }

    public String getArtifactHash() {
        return artifactHash;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public int getMaxBatchSize() {
        return maxBatchSize;
    }

    public long getFlushIntervalMs() {
        return flushIntervalMs;
    }

    public long getHttpTimeoutMs() {
        return httpTimeoutMs;
    }

    public long getPollIntervalMs() {
        return pollIntervalMs;
    }

    public long getDefaultApprovalTimeoutMs() {
        return defaultApprovalTimeoutMs;
    }

    public DropPolicy getDropPolicy() {
        return dropPolicy;
    }

    public static class Builder {
        private String ingestUrl = "http://localhost:8081/api/v1/ml/ingest";
        private String aiSystemId;
        private String artifactHash;
        private int queueCapacity = 10_000;
        private int maxBatchSize = 50;
        private long flushIntervalMs = 50;
        private long httpTimeoutMs = 3_000;
        private long pollIntervalMs = 500;
        private long defaultApprovalTimeoutMs = 30_000;
        private DropPolicy dropPolicy = DropPolicy.DROP_NEWEST;

        public Builder ingestUrl(String ingestUrl) {
            this.ingestUrl = ingestUrl;
            return this;
        }

        public Builder aiSystemId(String aiSystemId) {
            this.aiSystemId = aiSystemId;
            return this;
        }

        public Builder artifactHash(String artifactHash) {
            this.artifactHash = artifactHash;
            return this;
        }

        public Builder queueCapacity(int queueCapacity) {
            this.queueCapacity = queueCapacity;
            return this;
        }

        public Builder maxBatchSize(int maxBatchSize) {
            this.maxBatchSize = maxBatchSize;
            return this;
        }

        public Builder flushIntervalMs(long flushIntervalMs) {
            this.flushIntervalMs = flushIntervalMs;
            return this;
        }

        public Builder httpTimeoutMs(long httpTimeoutMs) {
            this.httpTimeoutMs = httpTimeoutMs;
            return this;
        }

        public Builder pollIntervalMs(long pollIntervalMs) {
            this.pollIntervalMs = pollIntervalMs;
            return this;
        }

        public Builder defaultApprovalTimeoutMs(long defaultApprovalTimeoutMs) {
            this.defaultApprovalTimeoutMs = defaultApprovalTimeoutMs;
            return this;
        }

        public Builder dropPolicy(DropPolicy dropPolicy) {
            this.dropPolicy = dropPolicy;
            return this;
        }

        public ClientConfig build() {
            return new ClientConfig(this);
        }
    }
}
