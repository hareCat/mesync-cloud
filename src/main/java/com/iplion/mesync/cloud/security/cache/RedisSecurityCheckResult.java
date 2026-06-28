package com.iplion.mesync.cloud.security.cache;

public enum RedisSecurityCheckResult {
    OK,
    REPLAY,
    RATE_LIMIT,
    REVOKED
}
