package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.registration.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import com.iplion.mesync.cloud.security.request.common.UnregisteredDeviceAuthRequest;

import java.util.UUID;

public record StorePublicKeysAuthRequest(
    String base64Signature,
    UUID nonce,
    String base64SigningPublicKey,

    String inviteToken,
    String base64EncryptionPublicKey
) implements UnregisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "INVITATION_STORE_PUBLIC_KEYS",
            inviteToken(),
            base64EncryptionPublicKey(),
            base64SigningPublicKey(),
            nonce().toString()
        );
    }

    public static StorePublicKeysAuthRequest from(StorePublicKeysRequestDto request) {
        return new StorePublicKeysAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.base64SigningPublicKey(),
            request.inviteToken(),
            request.base64EncryptionPublicKey()
        );
    }

}
