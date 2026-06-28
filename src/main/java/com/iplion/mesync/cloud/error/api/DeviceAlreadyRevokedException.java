package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.util.UUID;

public class DeviceAlreadyRevokedException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String MESSAGE = "Device is already revoked.";

    public DeviceAlreadyRevokedException(UUID targetDevicePublicId) {
        super(
            STATUS,
            String.format(
                MESSAGE + " targetDevicePublicId: %s",
                targetDevicePublicId
            ),
            MESSAGE
        );
    }
}
