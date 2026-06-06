package com.iplion.mesync.cloud.controller.dto;

import java.time.Instant;
import java.util.UUID;

public record DeviceRevokeResponseDto(
    UUID revokedDevicePublicId,
    Instant revokedAt
) {
}
