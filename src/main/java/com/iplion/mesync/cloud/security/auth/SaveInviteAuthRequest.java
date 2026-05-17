package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public record SaveInviteAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,
    UUID inviteToken,
    UUID publicId,
    String encryptedMasterKey,
    Integer keyVersion
) implements DeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "INVITATION",
            publicId().toString(),
            inviteToken().toString(),
            encryptedMasterKey,
            keyVersion.toString(),
            nonce().toString()
        );
    }

}
