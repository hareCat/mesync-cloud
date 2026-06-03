package com.iplion.mesync.cloud.model;

import java.security.PublicKey;
import java.util.UUID;

public record DeviceAuthData(
    Long deviceId,
    UUID devicePublicId,
    Long userId,
    UUID userAuthId,
    DeviceType deviceType,
    PublicKey publicKey,
    Integer userKeyVersion
) {
}