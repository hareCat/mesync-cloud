package com.iplion.mesync.cloud.error;

import org.springframework.http.HttpStatus;

public class InvalidDeviceTypeException extends ApplicationException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;
    private static final String MESSAGE = "Invalid device type";

    public InvalidDeviceTypeException(String internalMessage) {
        super(STATUS, internalMessage, MESSAGE);
    }
}
