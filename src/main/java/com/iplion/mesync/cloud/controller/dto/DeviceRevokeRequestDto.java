package com.iplion.mesync.cloud.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record DeviceRevokeRequestDto(
    @NotNull
    UUID publicId,

    @NotNull
    UUID targetDevicePublicId,

    boolean rotateMasterKey,

    @NotNull
    UUID nonce,

    @NotBlank
    @Size(min = 80, max = 120)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64Signature

) implements SignedRequest{
}
