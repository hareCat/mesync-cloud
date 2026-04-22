package com.iplion.mesync.cloud.model;

import java.util.UUID;

public record DeviceRegistrationVerificationData(
    String deviceName,
    DeviceType deviceType,
    String base64PublicKey,
    UUID inviteToken,
    String base64Signature
) {
}
