package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.registration.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;

import java.util.UUID;

public record StoreMasterKeyAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    String inviteToken,
    String encryptedMasterKey,
    Integer keyVersion
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "INVITATION_STORE_MASTER_KEY",
            devicePublicId().toString(),
            inviteToken(),
            encryptedMasterKey,
            keyVersion.toString(),
            nonce().toString()
        );
    }

    public static StoreMasterKeyAuthRequest from(StoreMasterKeyRequestDto request) {
        return new StoreMasterKeyAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.inviteToken(),
            request.base64EncryptedMasterKey(),
            request.keyVersion()
        );
    }

}
