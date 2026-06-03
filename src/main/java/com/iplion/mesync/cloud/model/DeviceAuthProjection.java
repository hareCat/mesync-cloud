package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.security.crypto.KeySignatureService;

import java.util.UUID;

public interface DeviceAuthProjection {
    Long getId();
    UUID getDevicePublicId();
    Long getUserId();
    UUID getUserAuthId();
    DeviceType getDeviceType();
    byte[] getPublicKeyBytes();
    Integer getUserKeyVersion();

    default DeviceAuthData toDeviceAuthData(KeySignatureService keySignatureService) {
        return new DeviceAuthData(
            getId(),
            getDevicePublicId(),
            getUserId(),
            getUserAuthId(),
            getDeviceType(),
            keySignatureService.createPublicKey(getPublicKeyBytes()),
            getUserKeyVersion()
        );
    }
}