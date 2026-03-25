package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;

import java.nio.charset.StandardCharsets;

public class DeviceRegistrationSignaturePayloadBuilder {

    private DeviceRegistrationSignaturePayloadBuilder() {}

    public static byte[] build(DeviceRegisterRequestDto context) {
        return String.join("\n",
            context.name(),
            context.deviceType().name(),
            context.base64PublicKey(),
            context.inviteToken() == null ? "" : context.inviteToken().toString()
        ).getBytes(StandardCharsets.UTF_8);
    }
}