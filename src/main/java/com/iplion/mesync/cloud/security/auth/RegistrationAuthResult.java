package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.model.JwtUserData;

import java.security.PublicKey;

public record RegistrationAuthResult(
    JwtUserData jwtUserData,
    PublicKey publicKey
) {
}
