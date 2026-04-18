package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class RedisOperationException extends ApplicationException {
    private static final String CLIENT_MESSAGE =
        "Storage is temporarily unavailable now. Please try again later.";
    private static final HttpStatus STATUS = HttpStatus.SERVICE_UNAVAILABLE;

    public RedisOperationException(String internalMessage) {
        super(STATUS, internalMessage, CLIENT_MESSAGE);
    }

    public RedisOperationException(String internalMessage, Throwable cause) {
        super(STATUS, internalMessage, CLIENT_MESSAGE, cause);
    }
}