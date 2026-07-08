package com.iplion.mesync.cloud.controller.dto.registration;

import java.time.Instant;

public record StorePublicKeysResponseDto(
    Instant expiresAt
) {
}
