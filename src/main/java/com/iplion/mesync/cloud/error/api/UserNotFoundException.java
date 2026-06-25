package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

import java.util.UUID;

public class UserNotFoundException extends ApiException {
    private static final HttpStatus STATUS = HttpStatus.INTERNAL_SERVER_ERROR;
    private static final String MESSAGE = "User not found.";

    public UserNotFoundException(UUID userAuthId) {
        super(STATUS, "There is no user with userAuthId: " + userAuthId + " in the database", MESSAGE);
    }
}
