package com.iplion.mesync.cloud.controller.dto;

import java.time.Instant;

public record StoreInviteResponseDto(
    Instant expiresAt
) {
}
