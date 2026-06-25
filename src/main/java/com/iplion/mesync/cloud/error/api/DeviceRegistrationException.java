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

    public static DeviceRegistrationException cooldownDelay(String redisKey, Duration cooldown) {
        long cooldownSeconds = cooldown.toSeconds();

        return new DeviceRegistrationException(
            HttpStatus.FORBIDDEN,
            String.format("RedisKey: %s. Cooldown %d seconds", redisKey, cooldownSeconds),
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

    public static DeviceRegistrationException inviteDeleteFailed(UUID authId, String inviteToken) {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            String.format("Failed to delete invite token. authId: %s, inviteToken: %s", authId, inviteToken),
            DEFAULT_CLIENT_MESSAGE
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

}
