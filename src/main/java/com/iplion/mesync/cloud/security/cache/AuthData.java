package com.iplion.mesync.cloud.security.cache;

public record AuthData(
    UserAuthData userAuthData,
    DeviceAuthData deviceAuthData
) {
}