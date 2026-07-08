package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import com.iplion.mesync.cloud.security.request.common.UnregisteredDeviceAuthRequest;

import java.util.Map;
import java.util.UUID;

public record RegistrationAuthRequest(
    String base64Signature,
    UUID nonce,
    String base64SigningPublicKey,

    String deviceName,
    Map<String, String> extras,
    String inviteToken
) implements UnregisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "REGISTRATION",
            inviteToken() == null ? "" : inviteToken(),
            base64SigningPublicKey(),
            deviceName() == null ? "" : deviceName(),
            nonce().toString()
        );
    }

    public static RegistrationAuthRequest from(DeviceRegisterRequestDto request) {
        return new RegistrationAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.base64PublicKey(),
            request.deviceName(),
            request.extras(),
            request.inviteToken()
        );
    }

}
