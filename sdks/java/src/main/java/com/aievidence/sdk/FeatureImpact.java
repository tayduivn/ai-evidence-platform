package com.aievidence.sdk;

/**
 * Represents the contribution score of an individual feature.
 */
public class FeatureImpact {
    private final String feature;
    private final double importance;
    private final String contribution;
    private final Object value;

    public FeatureImpact(String feature, double importance) {
        this(feature, importance, null, null);
    }

    public FeatureImpact(String feature, double importance, String contribution, Object value) {
        this.feature = feature;
        this.importance = importance;
        this.contribution = contribution;
        this.value = value;
    }

    public String getFeature() {
        return feature;
    }

    public double getImportance() {
        return importance;
    }

    public String getContribution() {
        return contribution;
    }

    public Object getValue() {
        return value;
    }
}
