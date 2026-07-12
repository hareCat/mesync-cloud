package com.iplion.mesync.cloud.error;

public class DeviceException extends RuntimeException {
    public DeviceException(String logMessage) {
        super(logMessage);
    }
}
