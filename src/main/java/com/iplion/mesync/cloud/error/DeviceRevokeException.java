package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

import java.util.UUID;

public class DeviceRevokeException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String MESSAGE = "Device is already revoked.";

    public DeviceRevokeException(long userId, long deviceId, UUID targetDevicePublicId) {
        super(
            STATUS,
            String.format(
                MESSAGE + " userId: %d, deviceId: %d, targetDevicePublicId: %s",
                userId, deviceId, targetDevicePublicId
            ),
            MESSAGE
        );
    }
}
