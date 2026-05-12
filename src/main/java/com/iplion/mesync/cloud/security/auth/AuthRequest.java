package com.iplion.mesync.cloud.security.auth;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public interface AuthRequest {
    Jwt jwt();

    String base64Signature();

    UUID nonce();

    byte[] payload();

}
