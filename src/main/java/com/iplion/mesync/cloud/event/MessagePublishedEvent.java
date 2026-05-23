package com.iplion.mesync.cloud.event;

public record MessagePublishedEvent(
    Long userId,
    Long excludeDeviceId
) {
}
