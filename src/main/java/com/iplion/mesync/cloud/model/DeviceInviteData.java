package com.iplion.mesync.cloud.model;

public record DeviceInviteData(
    String encryptedMasterKey,
    Integer keyVersion,
    DeviceType deviceType
) {
}
