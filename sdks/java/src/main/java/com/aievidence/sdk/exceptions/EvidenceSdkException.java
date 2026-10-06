package com.aievidence.sdk.exceptions;

/**
 * Base runtime exception for all AI Evidence SDK operations.
 */
public class EvidenceSdkException extends RuntimeException {

    public EvidenceSdkException(String message) {
        super(message);
    }

    public EvidenceSdkException(String message, Throwable cause) {
        super(message, cause);
    }
}
