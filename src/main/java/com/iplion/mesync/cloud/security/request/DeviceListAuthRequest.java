package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.device.DeviceListRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;

import java.util.UUID;

public record DeviceListAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "DEVICE_LIST",
            devicePublicId().toString(),
            nonce().toString()
        );
    }

    public static DeviceListAuthRequest from(DeviceListRequestDto request) {
        return new DeviceListAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId()
        );
    }

}
