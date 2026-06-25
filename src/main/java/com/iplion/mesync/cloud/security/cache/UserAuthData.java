package com.iplion.mesync.cloud.security.cache;

import com.iplion.mesync.cloud.entity.User;

import java.util.UUID;

public record UserAuthData(
    Long id,
    UUID authId,
    Integer keyVersion
) {
    public static UserAuthData from(User user) {
        return new UserAuthData(
            user.getId(),
            user.getAuthId(),
            user.getKeyVersion()
        );
    }
}