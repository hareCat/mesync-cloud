package com.iplion.mesync.cloud.infrastructure.redis;

import java.util.UUID;

public final class RedisKeys {
    private static final String REG_RATE_LIMIT = "mesync:cloud:reg:rate";
    private static final String REG_INVITE = "mesync:cloud:reg:invite";
    private static final String REG_INVITE_COOLDOWN = "mesync:cloud:reg:invite:cooldown";

    public static String registrationRateLimitKey(UUID authId) {
        return REG_RATE_LIMIT + ":" + authId;
    }

    public static String registrationInviteCooldownKey(UUID authId) {
        return REG_INVITE_COOLDOWN + ":" + authId;
    }

    public static String registrationInviteKey(UUID authId, UUID invite) {
        return REG_INVITE + ":" + authId + ":" + invite;
    }
}
