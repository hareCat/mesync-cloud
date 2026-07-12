package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class InvalidDeviceTypeException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;

    public InvalidDeviceTypeException(String logMessage) {
        super(STATUS, logMessage, ApiErrorCode.DEVICE_INVALID_TYPE);
    }
}
