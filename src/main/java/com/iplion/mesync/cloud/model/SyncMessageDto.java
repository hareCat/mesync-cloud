package com.iplion.mesync.cloud.model;

import java.time.Instant;
import java.util.UUID;

public record SyncMessageDto(
    Long id,
    UUID publicId,
    UUID devicePublicId,
    String address,
    MessageType messageType,
    MessageDirection direction,
    Instant occurredAt,
    Integer keyVersion,
    byte[] ciphertext
) {}
