package com.iplion.mesync.cloud.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public abstract class ApiException extends RuntimeException {
    private final HttpStatus httpStatus;
    private final String clientMessage;

    public ApiException(HttpStatus status, String internalMessage, String clientMessage) {
        this(status, internalMessage, clientMessage, null);
    }

    public ApiException(HttpStatus status, String internalMessage, String clientMessage, Throwable cause) {
        super(internalMessage, cause);
        this.clientMessage = clientMessage;
        httpStatus = status;
    }
}