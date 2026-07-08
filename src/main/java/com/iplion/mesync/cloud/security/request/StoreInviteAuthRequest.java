package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.registration.StoreInviteRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;

import java.util.UUID;

public record StoreInviteAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    String inviteToken,
    DeviceType deviceType,
    Integer keyVersion
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "INVITATION_STORE_INVITE",
            devicePublicId().toString(),
            inviteToken(),
            deviceType.toString(),
            keyVersion.toString(),
            nonce().toString()
        );
    }

    public static StoreInviteAuthRequest from(StoreInviteRequestDto request) {
        return new StoreInviteAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.inviteToken(),
            request.deviceType(),
            request.keyVersion()
        );
    }

}
