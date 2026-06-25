package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class RedisOperationException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.INTERNAL_SERVER_ERROR;
    private static final String CLIENT_MESSAGE = "Unable to process your request now. Please try again.";

    public RedisOperationException(String internalMessage) {
        super(STATUS, internalMessage, CLIENT_MESSAGE);
    }

    public RedisOperationException(String internalMessage, Throwable cause) {
        super(STATUS, internalMessage, CLIENT_MESSAGE, cause);
    }

}