package com.aievidence.sdk.exceptions;

/**
 * Thrown when a human-in-the-loop approval request exceeds the configured polling timeout.
 */
public class ApprovalTimeoutException extends EvidenceSdkException {

    private final String decisionId;
    private final String correlationId;

    public ApprovalTimeoutException(String message, String decisionId, String correlationId) {
        super(message);
        this.decisionId = decisionId;
        this.correlationId = correlationId;
    }

    public String getDecisionId() {
        return decisionId;
    }

    public String getCorrelationId() {
        return correlationId;
    }
}
