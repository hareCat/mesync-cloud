package com.iplion.mesync.cloud.controller.dto.registration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record StorePublicKeysRequestDto(
    @NotBlank
    @Pattern(regexp = "^[A-Z0-9]{6}$")
    String inviteToken,

    // public key for the master key encryption
    @NotBlank
    @Size(min = 44, max = 80)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64EncryptionPublicKey,

    // public key for signing requests
    @NotBlank
    @Size(min = 44, max = 80)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64SigningPublicKey,

    @NotNull
    UUID nonce,

    @NotBlank
    @Size(min = 80, max = 120)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64Signature

) {
}