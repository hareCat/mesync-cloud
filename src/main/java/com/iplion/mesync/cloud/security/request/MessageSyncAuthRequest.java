package com.iplion.mesync.cloud.security.request;

import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;

import java.util.UUID;

public record MessageSyncAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    Long lastMessageId,
    Integer limit
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "MESSAGE_SYNC",
            devicePublicId().toString(),
            lastMessageId().toString(),
            limit().toString(),
            nonce().toString()
        );
    }

    public static MessageSyncAuthRequest from(MessageSyncRequestDto request) {
        return new MessageSyncAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.lastMessageId(),
            request.limit()
        );
    }

}
