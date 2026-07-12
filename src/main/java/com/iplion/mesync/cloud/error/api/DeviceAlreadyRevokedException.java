package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.util.UUID;

public class DeviceAlreadyRevokedException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;

    public DeviceAlreadyRevokedException(UUID targetDevicePublicId) {
        super(
            STATUS,
            String.format(
                "Device is already revoked. targetDevicePublicId: %s",
                targetDevicePublicId
            ),
            ApiErrorCode.DEVICE_ALREADY_REVOKED
        );
    }
}
