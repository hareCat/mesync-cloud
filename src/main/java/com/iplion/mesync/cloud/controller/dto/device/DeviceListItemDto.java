package com.iplion.mesync.cloud.controller.dto.device;

import com.iplion.mesync.cloud.model.DeviceType;

import java.time.Instant;
import java.util.UUID;

public record DeviceListItemDto(
    UUID devicePublicId,
    DeviceType deviceType,
    String name,
    Instant createdAt,
    Instant revokedAt,
    Instant lastActiveAt
) {
}
