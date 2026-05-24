package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public record RegistrationAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,

    String base64PublicKey,
    UUID inviteToken
) implements AuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "REGISTRATION",
            inviteToken() == null ? "" : inviteToken().toString(),
            base64PublicKey(),
            nonce().toString()
        );
    }

    public static RegistrationAuthRequest from(Jwt jwt, DeviceRegisterRequestDto request) {
        return new RegistrationAuthRequest(
            jwt,
            request.base64Signature(),
            request.nonce(),
            request.base64PublicKey(),
            request.inviteToken()
        );
    }

}
