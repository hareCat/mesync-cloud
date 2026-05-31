package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class DeviceNotFoundException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String MESSAGE = "Device not found.";

    public DeviceNotFoundException(String internalMessage) {
        super(STATUS, internalMessage, MESSAGE);
    }
}
