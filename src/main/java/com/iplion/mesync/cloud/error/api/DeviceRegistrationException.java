package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.time.Duration;

public class DeviceRegistrationException extends ApiException {
    private static final String DEFAULT_CLIENT_MESSAGE = "Unable to complete device registration. Please try again.";

    private DeviceRegistrationException(HttpStatus status, String internalMessage, String clientMessage) {
        super(status, internalMessage, clientMessage);
    }

    private DeviceRegistrationException(HttpStatus status, String internalMessage, String clientMessage, Throwable cause) {
        super(status, internalMessage, clientMessage, cause);
    }

    public static DeviceRegistrationException cooldownDelay(Duration cooldown) {
        long cooldownSeconds = cooldown.toSeconds();

        return new DeviceRegistrationException(
            HttpStatus.FORBIDDEN,
            String.format("Registration cooldown is active. cooldownSeconds: %d", cooldownSeconds),
            String.format("You can send such request every %d seconds", cooldownSeconds)
        );
    }

    public static DeviceRegistrationException invalidInvite(String internalMessage) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Invalid invite"
        );
    }

    public static DeviceRegistrationException inviteDeleteFailed() {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to delete invite token.",
            DEFAULT_CLIENT_MESSAGE
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
            "Your master key version is outdated. Please update it."
        );
    }

    public static DeviceRegistrationException firstDeviceType() {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            "First device is not mobile.",
            "The first device must be registered from a mobile client."
        );
    }

    public static DeviceRegistrationException saveFailed(Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to persist device.",
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static DeviceRegistrationException userSaveFailed(Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to save user.",
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

}
