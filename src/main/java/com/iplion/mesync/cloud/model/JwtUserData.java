package com.iplion.mesync.cloud.model;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record JwtUserData(
    @NotNull UUID authId,
    @NotNull String clientId,
    String email,
    boolean emailVerified
) {
}
