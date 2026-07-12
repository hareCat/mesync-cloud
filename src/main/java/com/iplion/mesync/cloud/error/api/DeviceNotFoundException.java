package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class DeviceNotFoundException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.NOT_FOUND;

    public DeviceNotFoundException(String logMessage) {
        super(STATUS, logMessage, ApiErrorCode.DEVICE_NOT_FOUND);
    }
}
