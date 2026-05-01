package com.iplion.mesync.cloud.security.dto;

public record RedisDeviceRequestResultDto(
    String publicKey,
    boolean isRevoked,
    boolean isReplay,
    boolean isRateLimited
) {
}
