package com.iplion.mesync.cloud.error.api;

import lombok.Getter;
import org.springframework.http.HttpStatus;

public abstract class ApiException extends RuntimeException {
    @Getter
    private final HttpStatus httpStatus;

    @Getter
    private final ApiErrorCode errorCode;

    private final Object[] messageArgs;

    ApiException(HttpStatus status, String logMessage, ApiErrorCode errorCode, Object... messageArgs) {
        this(status, logMessage, errorCode, null, messageArgs);
    }

    ApiException(
        HttpStatus status,
        String logMessage,
        ApiErrorCode errorCode,
        Throwable cause,
        Object... messageArgs
    ) {
        super(logMessage, cause);
        this.errorCode = errorCode;
        this.messageArgs = messageArgs == null ? null : messageArgs.clone();
        this.httpStatus = status;
    }

    public Object[] getMessageArgs() {
        return messageArgs == null ? null : messageArgs.clone();
    }

}
