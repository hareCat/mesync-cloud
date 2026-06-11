package com.iplion.mesync.cloud.security.cache;

import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;

import java.util.UUID;

public interface AuthDataProjection {
    Long getId();

    UUID getDevicePublicId();

    Long getUserId();

    UUID getUserAuthId();

    DeviceType getDeviceType();

    byte[] getPublicKeyBytes();

    Integer getUserKeyVersion();

    default AuthData toAuthContext(KeySignatureService keySignatureService) {
        return new AuthData(
            new UserAuthData(
                getUserId(),
                getUserAuthId(),
                getUserKeyVersion()
            ),
            new DeviceAuthData(
                getId(),
                getDevicePublicId(),
                getDeviceType(),
                keySignatureService.createPublicKey(getPublicKeyBytes())
            )
        );
    }
}
