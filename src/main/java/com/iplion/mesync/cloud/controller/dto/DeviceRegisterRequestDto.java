package com.iplion.mesync.cloud.controller.dto;

import com.iplion.mesync.cloud.model.DeviceType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.Map;
import java.util.UUID;

public record DeviceRegisterRequestDto(
    @NotBlank
    @Size(max = 100)
    String name,

    @NotNull
    DeviceType deviceType,

    // base64(X509 Ed25519)
    @NotBlank
    @Size(max = 80)
    String base64PublicKey,

    @Size(max = 10)
    Map<String, String> extras,

    UUID inviteToken,

    @NotBlank
    @Size(max = 512)
    String base64Signature
) {
}
