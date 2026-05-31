package com.iplion.mesync.cloud.event;

import java.util.UUID;

public record DeviceRevokedEvent(
    UUID targetDevicePublicId
) {
}
