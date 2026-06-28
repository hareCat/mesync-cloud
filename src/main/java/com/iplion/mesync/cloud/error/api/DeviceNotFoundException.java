package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class DeviceNotFoundException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.NOT_FOUND;
    private static final String MESSAGE = "Device not found.";

    public DeviceNotFoundException(String internalMessage) {
        super(STATUS, internalMessage, MESSAGE);
    }
}
