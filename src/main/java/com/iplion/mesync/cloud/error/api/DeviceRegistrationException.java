package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.UUID;

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
            String.format("Invite cooldown %d seconds", cooldownSeconds),
            String.format("You can send one invitation every %d seconds", cooldownSeconds)
        );
    }

    public static DeviceRegistrationException redisSetValueError(UUID authId, Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            String.format("Couldn't set redis value, authId=%s", authId.toString()),
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static DeviceRegistrationException invalidInvite(String internalMessage) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Invalid invite"
        );
    }

    public static DeviceRegistrationException masterKeyVersionMismatch(
        long userId,
        long deviceId,
        Integer userMasterKeyVersion,
        Integer deviceMasterKeyVersion
    ) {
        return new DeviceRegistrationException(
            HttpStatus.CONFLICT,
            String.format("Master key version mismatch. " +
                    "userId: %d, deviceId: %d, userMasterKeyVersion: %d, deviceMasterKeyVersion: %d",
                userId, deviceId, userMasterKeyVersion, deviceMasterKeyVersion
            ),
            "Your master key version is outdated. Please update it."
        );
    }

    public static DeviceRegistrationException firstDeviceType(UUID authId) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            "First device is not mobile. authId: " + authId,
            "The first device must be registered from a mobile client."
        );
    }

    public static DeviceRegistrationException saveFailed(UUID authId, Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to persist device. authId: " + authId,
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static DeviceRegistrationException userSaveFailed(UUID authId, Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to save user. authId: " + authId,
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static DeviceRegistrationException deviceTypeMismatch(String internalMessage, String clientMessage) {
        return new DeviceRegistrationException(
            HttpStatus.FORBIDDEN,
            internalMessage,
            clientMessage
        );
    }

    public static DeviceRegistrationException wrongRegisterData(String internalMessage, Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

}
