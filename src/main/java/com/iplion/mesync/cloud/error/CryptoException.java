package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class CryptoException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String CLIENT_MESSAGE = "Signature verification failed";

    public CryptoException(String internalMessage, Throwable e) {
        super(STATUS, internalMessage, CLIENT_MESSAGE, e);
    }

    public CryptoException(String internalMessage) {
        super(STATUS, internalMessage, CLIENT_MESSAGE);
    }
}
