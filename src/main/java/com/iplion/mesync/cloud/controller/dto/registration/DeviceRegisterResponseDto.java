package com.iplion.mesync.cloud.controller.dto.registration;

import java.util.UUID;

public record DeviceRegisterResponseDto(
    UUID devicePublicId,
    String deviceName,
    String encryptedMasterKey,
    Integer keyVersion
) {
}
