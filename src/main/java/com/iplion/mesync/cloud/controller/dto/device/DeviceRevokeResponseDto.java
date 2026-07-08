package com.iplion.mesync.cloud.controller.dto.device;

import java.time.Instant;
import java.util.UUID;

public record DeviceRevokeResponseDto(
    UUID revokedDevicePublicId,
    Instant revokedAt
) {
}
