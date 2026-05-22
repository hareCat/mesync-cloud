package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public record MessageSyncAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,
    UUID publicId,

    Long lastMessageId
) implements DeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "MESSAGE_SYNC",
            publicId().toString(),
            lastMessageId().toString(),
            nonce().toString()
        );
    }

    public static MessageSyncAuthRequest from(Jwt jwt, MessageSyncRequestDto request) {
        return new MessageSyncAuthRequest(
            jwt,
            request.base64Signature(),
            request.nonce(),
            request.publicId(),
            request.lastMessageId()
        );
    }

}
