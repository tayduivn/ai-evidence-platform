package com.aievidence.sdk;

/**
 * Lifecycle states of an AI decision approval workflow.
 */
public enum ApprovalStatus {
    PENDING,
    PENDING_APPROVAL,
    AWAITING_SECOND_APPROVAL,
    APPROVED,
    REJECTED,
    EXPIRED;

    /**
     * Checks if the status represents a final terminal state.
     */
    public boolean isTerminal() {
        return this == APPROVED || this == REJECTED || this == EXPIRED;
    }

    /**
     * Checks if the status is APPROVED.
     */
    public boolean isApproved() {
        return this == APPROVED;
    }

    /**
     * Parse a status string safely, case-insensitively.
     */
    public static ApprovalStatus fromString(String val) {
        if (val == null || val.isBlank()) {
            return PENDING;
        }
        String clean = val.trim().toUpperCase();
        for (ApprovalStatus s : values()) {
            if (s.name().equals(clean)) {
                return s;
            }
        }
        return PENDING;
    }
}
