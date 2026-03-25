package com.iplion.mesync.cloud.infrastructure.redis;

import java.util.UUID;

public final class RedisKeys {
    private static final String REG_RATE_LIMIT = "mesync:cloud:reg:rate";
    private static final String REG_INVITE = "mesync:cloud:reg:invite";
    private static final String REG_INVITE_COOLDOWN = "mesync:cloud:reg:invite:cooldown";

    public static String registrationRateLimitKey(UUID sub) {
        return REG_RATE_LIMIT + ":" + sub;
    }

    public static String registrationInviteCooldownKey(UUID sub) {
        return REG_INVITE_COOLDOWN + ":" + sub;
    }

    public static String registrationInviteKey(UUID sub, UUID invite) {
        return REG_INVITE + ":" + sub + ":" + invite;
    }
}
