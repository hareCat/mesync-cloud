package com.iplion.mesync.cloud.controller.dto;

import com.iplion.mesync.cloud.model.DeviceType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record DeviceInviteRequestDto(
    @NotNull
    UUID inviteToken,

    @NotBlank
    @Size(min = 32, max = 8192, message = "Master Key size is invalid")
    String encryptedMasterKey,

    @NotNull
    DeviceType deviceType
) {
}