package com.iplion.mesync.cloud.model;

import java.util.UUID;

public record JwtUserData(
    UUID id,
    String clientId,
    String email,
    boolean isEmailVerified
) {
}
