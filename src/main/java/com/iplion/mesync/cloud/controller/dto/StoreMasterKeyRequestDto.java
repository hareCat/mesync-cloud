package com.iplion.mesync.cloud.controller.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record StoreMasterKeyRequestDto(
    @NotNull
    UUID devicePublicId,

    @NotBlank
    @Pattern(regexp = "^[A-Z0-9]{6}$")
    String inviteToken,

    @NotBlank
    @Size(min = 32, max = 512)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64EncryptedMasterKey,

    @NotNull
    @Min(1)
    Integer keyVersion,

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