package com.iplion.mesync.cloud.security.cache;

import com.iplion.mesync.cloud.model.DeviceType;

import java.security.PublicKey;
import java.util.UUID;

public record DeviceAuthData(
    Long id,
    UUID publicId,
    UUID ownerAuthId,
    DeviceType deviceType,
    PublicKey publicKey
) {
}
