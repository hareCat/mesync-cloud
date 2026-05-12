package com.iplion.mesync.cloud.error;

public class InvalidPublicKeyException extends RuntimeException {
    public InvalidPublicKeyException(String internalMessage) {
        super(internalMessage);
    }

    public InvalidPublicKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
