package com.iplion.mesync.cloud.controller.dto.message;

import java.util.UUID;

public record MessagePublishResponseDto(
    UUID messagePublicId
) {
}
