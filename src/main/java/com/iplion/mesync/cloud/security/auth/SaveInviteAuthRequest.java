package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;

import java.util.UUID;

public record SaveInviteAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    UUID inviteToken,
    String encryptedMasterKey,
    Integer keyVersion
) implements DeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "INVITATION",
            devicePublicId().toString(),
            inviteToken().toString(),
            encryptedMasterKey,
            keyVersion.toString(),
            nonce().toString()
        );
    }

    public static SaveInviteAuthRequest from(SaveInviteRequestDto request) {
        return new SaveInviteAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.inviteToken(),
            request.encryptedMasterKey(),
            request.keyVersion()
        );
    }

}
