package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.security.crypto.KeySignatureService;

import java.util.UUID;

public interface DeviceAuthProjection {
    Long getId();
    UUID getPublicId();
    Long getUserId();
    UUID getUserAuthId();
    DeviceType getDeviceType();
    byte[] getPublicKey();

    default DeviceAuthData toDeviceAuthData(KeySignatureService keySignatureService) {
        return new DeviceAuthData(
            getId(),
            getPublicId(),
            getUserId(),
            getUserAuthId(),
            getDeviceType(),
            keySignatureService.createPublicKey(getPublicKey())
        );
    }
}