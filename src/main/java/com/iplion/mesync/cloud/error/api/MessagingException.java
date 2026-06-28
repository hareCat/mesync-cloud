package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class MessagingException extends ApiException {

    private MessagingException(HttpStatus status, String internalMessage, String clientMessage, Throwable cause) {
        super(status, internalMessage, clientMessage, cause);
    }

    public static MessagingException messageSaving(String internalMessage, Throwable cause) {
        return new MessagingException(
            HttpStatus.CONFLICT,
            internalMessage,
            "Unable to save the message.",
            cause
        );
    }

    public static MessagingException invalidCryptographyData(String internalMessage, Throwable cause) {
        return new MessagingException(
            HttpStatus.BAD_REQUEST,
            internalMessage,
            "Cryptography data is not valid",
            cause
        );
    }

}
