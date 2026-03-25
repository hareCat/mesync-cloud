package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.error.InvalidDeviceTypeException;

public enum DeviceType {
    MOBILE("mesync-mobile"),
    BROWSER("mesync-browser"),
    DESKTOP("mesync-desktop");

    private final String keycloakClientId;

    DeviceType(String keycloakClientId) {
        this.keycloakClientId = keycloakClientId;
    }

    public static DeviceType fromClientId(String keycloakClientId) {
        if (keycloakClientId == null || keycloakClientId.isBlank()) {
            throw new InvalidDeviceTypeException("ClientId is null or blank");
        }

        String clientId = keycloakClientId.trim().toLowerCase();
        for (DeviceType deviceType : DeviceType.values()) {
            if (deviceType.keycloakClientId.equals(clientId)) {
                return deviceType;
            }
        }

        throw new InvalidDeviceTypeException("Unknown clientId: " + keycloakClientId);
    }
}
