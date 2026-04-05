package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.error.InvalidDeviceTypeException;
import lombok.Getter;

@Getter
public enum DeviceType {
    MOBILE("mesync-mobile"),
    BROWSER("mesync-browser"),
    DESKTOP("mesync-desktop");

    private final String clientId;

    DeviceType(String clientId) {
        this.clientId = clientId;
    }

    public static DeviceType fromClientId(String authClientId) {
        if (authClientId == null || authClientId.isBlank()) {
            throw new InvalidDeviceTypeException("ClientId is null or blank");
        }

        String clientId = authClientId.trim().toLowerCase();
        for (DeviceType deviceType : DeviceType.values()) {
            if (deviceType.clientId.equals(clientId)) {
                return deviceType;
            }
        }

        throw new InvalidDeviceTypeException("Unknown clientId: " + authClientId);
    }
}
