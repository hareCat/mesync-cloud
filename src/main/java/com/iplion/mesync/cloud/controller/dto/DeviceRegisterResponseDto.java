package com.iplion.mesync.cloud.controller.dto;

import java.util.UUID;

public record DeviceRegisterResponseDto(
    UUID deviceId,
    String encryptedMasterKey
) {
}
