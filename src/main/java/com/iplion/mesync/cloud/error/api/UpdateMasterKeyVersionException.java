package com.iplion.mesync.cloud.error.api;

import org.springframework.http.HttpStatus;

public class UpdateMasterKeyVersionException extends ApiException {
    private static final HttpStatus status = HttpStatus.BAD_REQUEST;

    public UpdateMasterKeyVersionException(String logMessage) {
        super(status, logMessage, ApiErrorCode.MASTER_KEY_VERSION_NOT_ALLOWED);
    }
}
