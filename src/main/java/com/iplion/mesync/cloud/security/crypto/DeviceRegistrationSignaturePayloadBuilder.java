package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.model.DeviceRegistrationPayload;

import java.nio.charset.StandardCharsets;

public class DeviceRegistrationSignaturePayloadBuilder {

    private DeviceRegistrationSignaturePayloadBuilder() {}

    public static byte[] build(DeviceRegistrationPayload payload) {
        return String.join("\nv1",
            payload.name(),
            payload.deviceType().name(),
            payload.base64PublicKey(),
            payload.inviteToken() == null ? "" : payload.inviteToken().toString()
        ).getBytes(StandardCharsets.UTF_8);
    }
}