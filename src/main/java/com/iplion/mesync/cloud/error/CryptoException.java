package com.iplion.mesync.cloud.error;

public class CryptoException extends RuntimeException {
    public CryptoException(String message, Throwable e) {
        super(message, e);
    }

    public CryptoException(String message) {
        super(message);
    }
}
