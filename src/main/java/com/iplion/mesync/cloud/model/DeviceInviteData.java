package com.iplion.mesync.cloud.model;

public record DeviceInviteData(
    String encryptedMasterKey,
    DeviceType deviceType
) {
}
