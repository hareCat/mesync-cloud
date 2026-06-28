package com.iplion.mesync.cloud.error.api;

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

    public static AuthException rateLimit() {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Auth rate limit exceeded.",
            "Too many requests"
        );
    }

    public static AuthException replay() {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Nonce already used.",
            "Replay request detected"
        );
    }

    public static AuthException revoked() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device revoked.",
            "Unable to verify your device."
        );
    }

    public static AuthException deviceNotTrusted() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device is not trusted or not found.",
            DEFAULT_CLIENT_MESSAGE
        );
    }

    public static AuthException invalidCryptographyData(String internalMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Cryptography data is not valid",
            cause
        );
    }

    public static AuthException signatureVerificationFailed(String internalMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            internalMessage,
            DEFAULT_CLIENT_MESSAGE,
            cause
        );
    }

    public static AuthException deviceOwnershipMismatch() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device owner mismatch.",
            "Device owner mismatch"
        );
    }

    public static AuthException securityContextError(String internalMessage) {
        return new AuthException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            internalMessage,
            "Authentication context error"
        );
    }

    public static AuthException userNotFound(UUID userAuthId) {
        return new AuthException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "There is no user with userAuthId: " + userAuthId + " in the database",
            "User not found."
        );
    }

    public static AuthException deviceTypeMismatch(
        DeviceType jwtDeviceType,
        DeviceType dbDeviceType
    ) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            String.format(
                "Device type mismatch. jwtDT: %s, dbDT: %s",
                jwtDeviceType.name(),
                dbDeviceType.name()
            ),
            DEFAULT_CLIENT_MESSAGE
        );
    }

}
