package com.iplion.mesync.cloud.controller.dto.message;

import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;

import java.time.Instant;
import java.util.UUID;

public record SyncMessageDto(
    Long id,
    UUID messagePublicId,
    UUID devicePublicId,
    String address,
    MessageType messageType,
    MessageDirection direction,
    Instant occurredAt,
    Integer keyVersion,
    byte[] ciphertext
) {}
