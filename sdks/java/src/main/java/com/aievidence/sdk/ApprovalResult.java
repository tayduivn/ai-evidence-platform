package com.aievidence.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * POJO representing the result or current status of an approval request.
 */
public class ApprovalResult {

    private final String decisionId;
    private final String correlationId;
    private final ApprovalStatus status;
    private final String pollUrl;
    private final String rejectionReason;
    private final List<String> approvers;

    public ApprovalResult(
            String decisionId,
            String correlationId,
            ApprovalStatus status,
            String pollUrl,
            String rejectionReason,
            List<String> approvers) {
        this.decisionId = decisionId;
        this.correlationId = correlationId;
        this.status = status != null ? status : ApprovalStatus.PENDING;
        this.pollUrl = pollUrl;
        this.rejectionReason = rejectionReason;
        this.approvers = approvers != null ? Collections.unmodifiableList(new ArrayList<>(approvers)) : Collections.emptyList();
    }

    public static ApprovalResult pending(String decisionId, String correlationId, String pollUrl) {
        return new ApprovalResult(decisionId, correlationId, ApprovalStatus.PENDING_APPROVAL, pollUrl, null, Collections.emptyList());
    }

    public static ApprovalResult approved(String decisionId, String correlationId, List<String> approvers) {
        return new ApprovalResult(decisionId, correlationId, ApprovalStatus.APPROVED, null, null, approvers);
    }

    public static ApprovalResult rejected(String decisionId, String correlationId, String reason) {
        return new ApprovalResult(decisionId, correlationId, ApprovalStatus.REJECTED, null, reason, Collections.emptyList());
    }

    public static ApprovalResult expired(String decisionId, String correlationId) {
        return new ApprovalResult(decisionId, correlationId, ApprovalStatus.EXPIRED, null, "Approval request expired", Collections.emptyList());
    }

    public String getDecisionId() {
        return decisionId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public ApprovalStatus getStatus() {
        return status;
    }

    public String getPollUrl() {
        return pollUrl;
    }

    public String getRejectionReason() {
        return rejectionReason;
    }

    public List<String> getApprovers() {
        return approvers;
    }

    public boolean isApproved() {
        return status == ApprovalStatus.APPROVED;
    }

    public boolean isTerminal() {
        return status != null && status.isTerminal();
    }

    @Override
    public String toString() {
        return "ApprovalResult{" +
                "decisionId='" + decisionId + '\'' +
                ", correlationId='" + correlationId + '\'' +
                ", status=" + status +
                ", pollUrl='" + pollUrl + '\'' +
                ", rejectionReason='" + rejectionReason + '\'' +
                ", approvers=" + approvers +
                '}';
    }
}
