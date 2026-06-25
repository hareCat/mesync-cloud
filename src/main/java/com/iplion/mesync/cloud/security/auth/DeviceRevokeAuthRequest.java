package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;

import java.util.UUID;

public record DeviceRevokeAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    UUID targetDevicePublicId,
    Integer currentMasterKeyVersion
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "REVOCATION",
            devicePublicId().toString(),
            targetDevicePublicId().toString(),
            currentMasterKeyVersion().toString(),
            nonce().toString()
        );
    }

    public static DeviceRevokeAuthRequest from(DeviceRevokeRequestDto request) {
        return new DeviceRevokeAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.targetDevicePublicId(),
            request.deviceMasterKeyVersion()
        );
    }

}
