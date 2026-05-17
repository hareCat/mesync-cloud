package com.iplion.mesync.cloud.model;

import java.security.PublicKey;
import java.util.UUID;

public record DeviceAuthData(
    Long id,
    UUID publicId,
    Long userId,
    UUID userAuthId,
    DeviceType deviceType,
    PublicKey publicKey,
    Integer userKeyVersion
) {
}