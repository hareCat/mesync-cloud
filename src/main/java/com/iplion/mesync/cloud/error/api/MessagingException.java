package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class MessagingException extends ApiException {

    private MessagingException(HttpStatus status, String logMessage, ApiErrorCode errorCode, Throwable cause) {
        super(status, logMessage, errorCode, cause);
    }

    public static MessagingException messageSaving(String logMessage, Throwable cause) {
        return new MessagingException(
            HttpStatus.CONFLICT,
            logMessage,
            ApiErrorCode.MESSAGE_SAVE_FAILED,
            cause
        );
    }

    public static MessagingException invalidCryptographyData(String logMessage, Throwable cause) {
        return new MessagingException(
            HttpStatus.BAD_REQUEST,
            logMessage,
            ApiErrorCode.CRYPTOGRAPHY_DATA_INVALID,
            cause
        );
    }

}
