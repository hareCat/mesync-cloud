package com.iplion.mesync.cloud.error;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String logMessage) {
        super(logMessage);
    }

    public InvalidTokenException(String logMessage, Throwable cause) {
        super(logMessage, cause);
    }
}
