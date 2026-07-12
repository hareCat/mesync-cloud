package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.time.Duration;

public class DeviceRegistrationException extends ApiException {
    private DeviceRegistrationException(HttpStatus status, String logMessage, ApiErrorCode errorCode) {
        super(status, logMessage, errorCode);
    }

    private DeviceRegistrationException(HttpStatus status, String logMessage, ApiErrorCode errorCode, Throwable cause) {
        super(status, logMessage, errorCode, cause);
    }

    private DeviceRegistrationException(
        HttpStatus status,
        String logMessage,
        ApiErrorCode errorCode,
        Object... messageArgs
    ) {
        super(status, logMessage, errorCode, messageArgs);
    }

    public static DeviceRegistrationException cooldownDelay(Duration cooldown) {
        long cooldownSeconds = cooldown.toSeconds();

        return new DeviceRegistrationException(
            HttpStatus.FORBIDDEN,
            String.format("Registration cooldown is active. cooldownSeconds: %d", cooldownSeconds),
            ApiErrorCode.REGISTRATION_COOLDOWN,
            cooldownSeconds
        );
    }

    public static DeviceRegistrationException invalidInvite(String logMessage) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            logMessage,
            ApiErrorCode.REGISTRATION_INVALID_INVITE
        );
    }

    public static DeviceRegistrationException inviteDeleteFailed() {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to delete invite token.",
            ApiErrorCode.REGISTRATION_DEFAULT
        );
    }

    public static DeviceRegistrationException masterKeyVersionMismatch(
        Integer userMasterKeyVersion,
        Integer deviceMasterKeyVersion
    ) {
        return new DeviceRegistrationException(
            HttpStatus.CONFLICT,
            String.format("Master key version mismatch. " +
                    "userMasterKeyVersion: %d, deviceMasterKeyVersion: %d",
                userMasterKeyVersion, deviceMasterKeyVersion
            ),
            ApiErrorCode.REGISTRATION_MASTER_KEY_VERSION_MISMATCH
        );
    }

    public static DeviceRegistrationException firstDeviceType() {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            "First device is not mobile.",
            ApiErrorCode.REGISTRATION_FIRST_DEVICE_TYPE
        );
    }

    public static DeviceRegistrationException saveFailed(Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to persist device.",
            ApiErrorCode.REGISTRATION_DEFAULT,
            cause
        );
    }

    public static DeviceRegistrationException userSaveFailed(Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to save user.",
            ApiErrorCode.REGISTRATION_DEFAULT,
            cause
        );
    }

}
