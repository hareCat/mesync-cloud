package com.iplion.mesync.cloud.error;

public class CryptoException extends RuntimeException {
    public CryptoException(String logMessage, Throwable e) {
        super(logMessage, e);
    }

    public CryptoException(String logMessage) {
        super(logMessage);
    }
}
