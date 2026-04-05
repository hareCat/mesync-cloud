package com.iplion.mesync.cloud.model;

import java.security.PublicKey;
import java.util.UUID;

public record DeviceRegistrationVerificationData(
    PublicKey publicKey,
    String deviceName,
    DeviceType deviceType,
    String base64PublicKey,
    UUID inviteToken,
    String base64Signature
) {
}
