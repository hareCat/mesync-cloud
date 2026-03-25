package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class InvalidPublicKeyException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String MESSAGE = "Invalid device public key";

    public InvalidPublicKeyException(String internalMessage) {
        super(STATUS, internalMessage, MESSAGE);
    }

    public InvalidPublicKeyException(String internalMessage, Throwable cause) {
        super(STATUS, internalMessage, MESSAGE, cause);
    }
}
