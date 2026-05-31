package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public record DeviceRevokeAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,
    UUID publicId,

    UUID targetDevicePublicId
) implements DeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "REVOCATION",
            publicId().toString(),
            targetDevicePublicId().toString(),
            nonce().toString()
        );
    }

    public static DeviceRevokeAuthRequest from(Jwt jwt, DeviceRevokeRequestDto request) {
        return new DeviceRevokeAuthRequest(
            jwt,
            request.base64Signature(),
            request.nonce(),
            request.publicId(),
            request.targetDevicePublicId()
        );
    }

}
