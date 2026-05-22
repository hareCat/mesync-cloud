package com.iplion.mesync.cloud.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;
import java.util.UUID;

public record DeviceRegisterRequestDto(
    @NotBlank
    @Size(max = 100)
    String deviceName,

    @NotBlank
    @Size(min = 44, max = 80)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64PublicKey,

    @Size(max = 10)
    Map<@Size(max = 50) String, @Size(max = 200) String>
    extras,

    UUID inviteToken,

    @NotNull
    UUID nonce,

    @NotBlank
    @Size(min = 80, max = 120)
    @Pattern(
        regexp = "^[A-Za-z0-9+/=]+$",
        message = "must be valid base64"
    )
    String base64Signature

) implements  SignedRequest {
}
