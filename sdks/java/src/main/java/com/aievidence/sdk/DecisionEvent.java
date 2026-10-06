package com.aievidence.sdk;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * POJO representing an ML model decision event for ingestion into the AI Evidence platform.
 */
public class DecisionEvent {

    private final String aiSystemId;
    private final String modelVersion;
    private final String artifactHash;
    private final Map<String, Object> features;
    private final Double score;
    private final String decision;
    private final Explanation explanation;
    private final String correlationId;
    private final boolean requiresApproval;
    private final String creatorId;

    private DecisionEvent(Builder builder) {
        this.aiSystemId = Objects.requireNonNull(builder.aiSystemId, "aiSystemId must not be null");
        this.modelVersion = builder.modelVersion;
        this.artifactHash = builder.artifactHash;
        this.features = builder.features != null ? Collections.unmodifiableMap(new HashMap<>(builder.features)) : Collections.emptyMap();
        this.score = builder.score;
        this.decision = builder.decision;
        this.explanation = builder.explanation;
        this.correlationId = builder.correlationId;
        this.requiresApproval = builder.requiresApproval;
        this.creatorId = builder.creatorId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getAiSystemId() {
        return aiSystemId;
    }

    public String getModelVersion() {
        return modelVersion;
    }

    public String getArtifactHash() {
        return artifactHash;
    }

    public Map<String, Object> getFeatures() {
        return features;
    }

    public Double getScore() {
        return score;
    }

    public String getDecision() {
        return decision;
    }

    public Explanation getExplanation() {
        return explanation;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public boolean isRequiresApproval() {
        return requiresApproval;
    }

    public String getCreatorId() {
        return creatorId;
    }

    /**
     * Create a copy with requiresApproval set to the specified value.
     */
    public DecisionEvent withRequiresApproval(boolean requiresApproval) {
        return new Builder()
                .aiSystemId(this.aiSystemId)
                .modelVersion(this.modelVersion)
                .artifactHash(this.artifactHash)
                .features(this.features)
                .score(this.score)
                .decision(this.decision)
                .explanation(this.explanation)
                .correlationId(this.correlationId)
                .requiresApproval(requiresApproval)
                .creatorId(this.creatorId)
                .build();
    }

    public static class Builder {
        private String aiSystemId;
        private String modelVersion;
        private String artifactHash;
        private Map<String, Object> features;
        private Double score;
        private String decision;
        private Explanation explanation;
        private String correlationId;
        private boolean requiresApproval = false;
        private String creatorId;

        public Builder aiSystemId(String aiSystemId) {
            this.aiSystemId = aiSystemId;
            return this;
        }

        public Builder modelVersion(String modelVersion) {
            this.modelVersion = modelVersion;
            return this;
        }

        public Builder artifactHash(String artifactHash) {
            this.artifactHash = artifactHash;
            return this;
        }

        public Builder features(Map<String, Object> features) {
            this.features = features;
            return this;
        }

        public Builder score(Double score) {
            this.score = score;
            return this;
        }

        public Builder decision(String decision) {
            this.decision = decision;
            return this;
        }

        public Builder explanation(Explanation explanation) {
            this.explanation = explanation;
            return this;
        }

        public Builder correlationId(String correlationId) {
            this.correlationId = correlationId;
            return this;
        }

        public Builder requiresApproval(boolean requiresApproval) {
            this.requiresApproval = requiresApproval;
            return this;
        }

        public Builder creatorId(String creatorId) {
            this.creatorId = creatorId;
            return this;
        }

        public DecisionEvent build() {
            return new DecisionEvent(this);
        }
    }
}
