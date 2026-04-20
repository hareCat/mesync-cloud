package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.UUID;

public class DeviceRegistrationException extends ApplicationException {
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

    public static DeviceRegistrationException invalidInvite(String internalMessage) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Invalid invite"
        );
    }

    public static DeviceRegistrationException rateLimit() {
        return new DeviceRegistrationException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Registration rate limit exceeded",
            "Too many requests"
        );
    }

    public static DeviceRegistrationException firstDeviceType() {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            "First device is not mobile",
            "The first device must be registered from a mobile client."
        );
    }

    public static DeviceRegistrationException invalidSignature(UUID authId, Throwable cause) {
        return new DeviceRegistrationException(
            HttpStatus.FORBIDDEN,
            "Invalid signature. AuthId=" + authId,
            "Signature is not valid",
            cause
        );
    }

    public static DeviceRegistrationException saveFailed() {
        return new DeviceRegistrationException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Failed to persist device",
            "Unable to complete device registration. Please try again."
        );
    }

    public static DeviceRegistrationException deviceTypeMismatch(String internalMessage) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Unable to complete device registration. Please try again."
        );
    }

    public static DeviceRegistrationException wrongRegisterData(String internalMessage, Throwable e) {
        return new DeviceRegistrationException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Unable to complete device registration. Please try again.",
            e
        );
    }
}
