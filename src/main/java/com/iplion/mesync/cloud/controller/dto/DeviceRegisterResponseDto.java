package com.iplion.mesync.cloud.controller.dto;

import java.util.UUID;

public record DeviceRegisterResponseDto(
    UUID publicId,
    String deviceName,
    String encryptedMasterKey,
    Integer keyVersion
) {
}
