package com.iplion.mesync.cloud.model;

import java.util.UUID;

public record DeviceRegistrationPayload(
    String name,
    DeviceType deviceType,
    String base64PublicKey,
    UUID inviteToken
) {
}
