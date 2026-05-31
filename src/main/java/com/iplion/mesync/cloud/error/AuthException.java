package com.iplion.mesync.cloud.error;

import com.iplion.mesync.cloud.model.DeviceType;
import org.springframework.http.HttpStatus;

import java.util.UUID;

public class AuthException extends ApiException {
    private static final String DEFAULT_CLIENT_MESSAGE = "Unable to verify your device.";

    private AuthException(HttpStatus status, String internalMessage, String clientMessage) {
        super(status, internalMessage, clientMessage);
    }

    private AuthException(HttpStatus status, String internalMessage, String clientMessage, Throwable cause) {
        super(status, internalMessage, clientMessage, cause);
    }

    public static AuthException wrongRequestData(String internalMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static AuthException redisOperationError(UUID authId, Throwable cause) {
        return new AuthException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            String.format("Couldn't set redis value, authId=%s", authId.toString()),
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static AuthException rateLimit(String key) {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Registration rate limit exceeded. redisKey: " + key,
            "Too many requests"
        );
    }

    public static AuthException replay(String key) {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Nonce already used. redisKey: " + key,
            "Replay request detected"
        );
    }

    public static AuthException revoked(String key) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device revoked. redisKey: " + key,
            "Replay request detected"
        );
    }

    public static AuthException cryptographyFailed(String internalMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            internalMessage,
            "Cryptography data is not valid",
            cause
        );
    }

    public static AuthException deviceNotFound(UUID authId, Throwable cause) {
        return new AuthException(
            HttpStatus.NOT_FOUND,
            "Device not found. authId: " + authId,
            "Device not found",
            cause
        );
    }

    public static AuthException deviceOwnershipMismatch(UUID jwtId, UUID deviceOwnerAuthId) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            String.format("Device owner mismatch. jwtId: %s, deviceOwnerAuthId: %s", jwtId, deviceOwnerAuthId),
            "Device owner mismatch"
        );
    }

    public static AuthException deviceTypeMismatch(
        UUID authId,
        UUID publicId,
        DeviceType jwtDeviceType,
        DeviceType dbDeviceType
    ) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            String.format(
                "Device type mismatch. authId: %s, publicId: %s, jwtDT: %s, dbDT: %s",
                authId.toString(),
                publicId.toString(),
                jwtDeviceType.name(),
                dbDeviceType.name()
            ),
            DEFAULT_CLIENT_MESSAGE
        );
    }

}
