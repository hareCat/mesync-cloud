package com.iplion.mesync.cloud.error.api;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ApiErrorCode {
    AUTH_DEFAULT("error.auth.default"),
    AUTH_RATE_LIMIT("error.auth.rate-limit"),
    AUTH_REPLAY("error.auth.replay"),
    AUTH_INVALID_CRYPTOGRAPHY_DATA("error.auth.invalid-cryptography-data"),
    AUTH_DEVICE_OWNERSHIP_MISMATCH("error.auth.device-ownership-mismatch"),
    AUTH_SECURITY_CONTEXT_ERROR("error.auth.security-context-error"),
    AUTH_USER_NOT_FOUND("error.auth.user-not-found"),

    REGISTRATION_DEFAULT("error.registration.default"),
    REGISTRATION_COOLDOWN("error.registration.cooldown"),
    REGISTRATION_INVALID_INVITE("error.registration.invalid-invite"),
    REGISTRATION_MASTER_KEY_VERSION_MISMATCH("error.registration.master-key-version-mismatch"),
    REGISTRATION_FIRST_DEVICE_TYPE("error.registration.first-device-type"),

    DEVICE_NOT_FOUND("error.device.not-found"),
    DEVICE_ALREADY_REVOKED("error.device.already-revoked"),
    DEVICE_INVALID_TYPE("error.device.invalid-type"),

    MESSAGE_SAVE_FAILED("error.message.save-failed"),
    CRYPTOGRAPHY_DATA_INVALID("error.cryptography-data-invalid"),

    MASTER_KEY_VERSION_NOT_ALLOWED("error.master-key-version.not-allowed"),
    REDIS_OPERATION_FAILED("error.redis.operation-failed"),

    MALFORMED_JSON("error.request.malformed-json"),
    VALIDATION_FAILED("error.request.validation-failed"),
    INVALID_REQUEST_PARAMETERS("error.request.invalid-parameters"),
    UNAUTHORIZED("error.auth.unauthorized"),
    ACCESS_DENIED("error.auth.access-denied"),
    INTERNAL_ERROR("error.internal");

    private final String messageKey;
}
