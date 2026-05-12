package com.iplion.mesync.cloud.model;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record JwtUserData(
    @NotNull UUID id,
    @NotNull String clientId,
    String email,
    boolean emailVerified
) {
}
