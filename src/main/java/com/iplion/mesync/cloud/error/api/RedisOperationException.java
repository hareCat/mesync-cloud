package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class RedisOperationException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.INTERNAL_SERVER_ERROR;

    public RedisOperationException(String logMessage) {
        super(STATUS, logMessage, ApiErrorCode.REDIS_OPERATION_FAILED);
    }

    public RedisOperationException(String logMessage, Throwable cause) {
        super(STATUS, logMessage, ApiErrorCode.REDIS_OPERATION_FAILED, cause);
    }

}
