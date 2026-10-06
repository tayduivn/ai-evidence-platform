package com.aievidence.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Model explainability outputs (e.g., SHAP feature importances).
 */
public class Explanation {
    private final String method;
    private final List<FeatureImpact> topFeatures;

    public Explanation(String method, List<FeatureImpact> topFeatures) {
        this.method = method != null ? method : "SHAP_TreeExplainer";
        this.topFeatures = topFeatures != null ? new ArrayList<>(topFeatures) : Collections.emptyList();
    }

    public String getMethod() {
        return method;
    }

    public List<FeatureImpact> getTopFeatures() {
        return Collections.unmodifiableList(topFeatures);
    }
}
