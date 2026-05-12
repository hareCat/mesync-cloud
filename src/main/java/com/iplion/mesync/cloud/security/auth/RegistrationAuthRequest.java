package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public record RegistrationAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,
    UUID inviteToken,
    String base64PublicKey
) implements PublicKeyAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "REGISTRATION",
            inviteToken().toString(),
            base64PublicKey(),
            nonce().toString()
        );
    }

}
