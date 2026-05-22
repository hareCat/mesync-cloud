package com.iplion.mesync.cloud.controller.dto;

import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.UUID;

public record MessagePublishRequestDto(
    @NotNull
    UUID publicId,

    @NotNull
    UUID messageId,

    @NotBlank
    @Size(max = 64)
    String address,

    @NotNull
    MessageType messageType,

    @NotNull
    MessageDirection direction,

    @NotNull
    Instant occurredAt,

    @NotNull
    @Min(1)
    Integer keyVersion,

    @NotBlank
    @Size(min = 16, max = 32768)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64Ciphertext,

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
