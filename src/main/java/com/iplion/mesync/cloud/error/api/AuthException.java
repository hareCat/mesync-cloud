package com.iplion.mesync.cloud.error.api;

import com.iplion.mesync.cloud.model.DeviceType;
import org.springframework.http.HttpStatus;

import java.util.UUID;

public class AuthException extends ApiException {
    private AuthException(HttpStatus status, String logMessage, ApiErrorCode errorCode) {
        super(status, logMessage, errorCode);
    }

    private AuthException(HttpStatus status, String logMessage, ApiErrorCode errorCode, Throwable cause) {
        super(status, logMessage, errorCode, cause);
    }

    public static AuthException wrongRequestData(String logMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.BAD_REQUEST,
            logMessage,
            ApiErrorCode.AUTH_DEFAULT,
            cause
        );
    }

    public static AuthException rateLimit() {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Auth rate limit exceeded.",
            ApiErrorCode.AUTH_RATE_LIMIT
        );
    }

    public static AuthException replay() {
        return new AuthException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Nonce already used.",
            ApiErrorCode.AUTH_REPLAY
        );
    }

    public static AuthException revoked() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device revoked.",
            ApiErrorCode.AUTH_DEFAULT
        );
    }

    public static AuthException deviceNotTrusted() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device is not trusted or not found.",
            ApiErrorCode.AUTH_DEFAULT
        );
    }

    public static AuthException invalidCryptographyData(String logMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.BAD_REQUEST,
            logMessage,
            ApiErrorCode.AUTH_INVALID_CRYPTOGRAPHY_DATA,
            cause
        );
    }

    public static AuthException signatureVerificationFailed(String logMessage, Throwable cause) {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            logMessage,
            ApiErrorCode.AUTH_DEFAULT,
            cause
        );
    }

    public static AuthException deviceOwnershipMismatch() {
        return new AuthException(
            HttpStatus.FORBIDDEN,
            "Device owner mismatch.",
            ApiErrorCode.AUTH_DEVICE_OWNERSHIP_MISMATCH
        );
    }

    public static AuthException securityContextError(String logMessage) {
        return new AuthException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            logMessage,
            ApiErrorCode.AUTH_SECURITY_CONTEXT_ERROR
        );
    }

    public static AuthException userNotFound(UUID userAuthId) {
        return new AuthException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "There is no user with userAuthId: " + userAuthId + " in the database",
            ApiErrorCode.AUTH_USER_NOT_FOUND
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
            ApiErrorCode.AUTH_DEFAULT
        );
    }

}
