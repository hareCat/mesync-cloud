package com.iplion.mesync.cloud.security.cache;

import java.util.UUID;

public record UserAuthData(
    Long id,
    UUID authId,
    Integer keyVersion
) {
}