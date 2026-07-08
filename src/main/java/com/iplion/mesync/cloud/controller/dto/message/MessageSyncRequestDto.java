package com.iplion.mesync.cloud.controller.dto.message;

import com.iplion.mesync.cloud.controller.dto.common.SignedRequest;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record MessageSyncRequestDto(
    @NotNull
    UUID devicePublicId,

    @PositiveOrZero
    long lastMessageId,

    @Min(1)
    int limit,

    @NotNull
    UUID nonce,

    @NotBlank
    @Size(min = 80, max = 120)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64Signature
) implements SignedRequest {
}