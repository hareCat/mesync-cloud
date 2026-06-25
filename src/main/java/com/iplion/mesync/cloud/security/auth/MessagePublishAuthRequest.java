package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;

import java.time.Instant;
import java.util.UUID;

public record MessagePublishAuthRequest(
    String base64Signature,
    UUID nonce,
    UUID devicePublicId,

    UUID messagePublicId,
    String address,
    MessageType messageType,
    MessageDirection direction,
    Instant occurredAt,
    Integer keyVersion,
    String base64Ciphertext
) implements RegisteredDeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "MESSAGE_PUBLISH",
            devicePublicId().toString(),
            messagePublicId().toString(),
            address(),
            messageType().name(),
            direction().name(),
            occurredAt().toString(),
            keyVersion().toString(),
            base64Ciphertext(),
            nonce().toString()
        );
    }

    public static MessagePublishAuthRequest from(MessagePublishRequestDto request) {
        return new MessagePublishAuthRequest(
            request.base64Signature(),
            request.nonce(),
            request.devicePublicId(),
            request.messagePublicId(),
            request.address(),
            request.messageType(),
            request.direction(),
            request.occurredAt(),
            request.keyVersion(),
            request.base64Ciphertext()
        );
    }

}
