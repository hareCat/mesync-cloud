package com.iplion.mesync.cloud.controller.dto;

import java.time.Instant;

public record DeviceInviteResponseDto(
    Instant expiresAt
) {
}
