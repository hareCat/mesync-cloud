package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class InvalidTokenException extends ApplicationException {
    private static final String CLIENT_MESSAGE = "Invalid token";
    private static final HttpStatus STATUS = HttpStatus.UNAUTHORIZED;

    public InvalidTokenException(String internalMessage) {
        super(STATUS, internalMessage, CLIENT_MESSAGE);
    }

    public InvalidTokenException(String internalMessage, Throwable cause) {
        super(STATUS, internalMessage, CLIENT_MESSAGE, cause);
    }
}