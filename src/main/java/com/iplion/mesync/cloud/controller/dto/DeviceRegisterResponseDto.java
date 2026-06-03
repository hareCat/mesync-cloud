package com.iplion.mesync.cloud.controller.dto;

import java.util.UUID;

public record DeviceRegisterResponseDto(
    UUID devicePublicId,
    String deviceName,
    String encryptedMasterKey,
    Integer keyVersion
) {
}
