package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class UpdateMasterKeyVersionException extends ApiException {
    private static final HttpStatus status = HttpStatus.BAD_REQUEST;
    private static final String clientMessage =
        "Required master key version is not allowed.";

    public UpdateMasterKeyVersionException(String internalMessage) {
        super(status, internalMessage, clientMessage);
    }
}
