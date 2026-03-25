package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

import java.util.UUID;

public class DeviceNotFoundException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.NOT_FOUND;
    private static final String CLIENT_MESSAGE = "Device not found";
    private static final String INTERNAL_MESSAGE = "Device not found: id=";

    public DeviceNotFoundException(UUID deviceId) {
        super(
            STATUS,
            INTERNAL_MESSAGE + deviceId,
            CLIENT_MESSAGE
        );
    }
}