package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.security.crypto.PayloadBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.UUID;

public record MessagePublishAuthRequest(
    Jwt jwt,
    String base64Signature,
    UUID nonce,
    UUID publicId,

    UUID messageId,
    String address,
    MessageType messageType,
    MessageDirection direction,
    Instant occurredAt,
    String base64Ciphertext
) implements DeviceAuthRequest {

    @Override
    public byte[] payload() {
        return PayloadBuilder.build(
            "MESSAGE_PUBLISH",
            publicId().toString(),
            messageId().toString(),
            address(),
            messageType().name(),
            direction().name(),
            occurredAt().toString(),
            base64Ciphertext(),
            nonce().toString()
        );
    }

    public static MessagePublishAuthRequest from(Jwt jwt, MessagePublishRequestDto request) {
        return new MessagePublishAuthRequest(
            jwt,
            request.base64Signature(),
            request.nonce(),
            request.publicId(),
            request.messageId(),
            request.address(),
            request.messageType(),
            request.direction(),
            request.occurredAt(),
            request.base64Ciphertext()
        );
    }

}
