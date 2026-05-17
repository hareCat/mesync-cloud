package com.iplion.mesync.cloud.controller.dto;

import com.iplion.mesync.cloud.model.DeviceType;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record SaveInviteRequestDto(
    @NotNull
    UUID publicId,

    @NotNull
    UUID inviteToken,

    @NotBlank
    @Size(min = 32, max = 512)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String encryptedMasterKey,

    @NotNull
    @Min(1)
    Integer keyVersion,

    @NotNull
    DeviceType deviceType,

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