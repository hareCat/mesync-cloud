package com.iplion.mesync.cloud.error;

public class InvalidPublicKeyException extends RuntimeException {
    public InvalidPublicKeyException(String logMessage) {
        super(logMessage);
    }

    public InvalidPublicKeyException(String logMessage, Throwable cause) {
        super(logMessage, cause);
    }
}
