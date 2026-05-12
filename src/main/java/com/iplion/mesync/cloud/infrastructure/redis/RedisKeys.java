package com.iplion.mesync.cloud.infrastructure.redis;

import java.util.UUID;

public final class RedisKeys {
    private static final String REG_RATE_LIMIT = "mesync:reg:rate";
    private static final String REG_INVITE = "mesync:reg:invite";
    private static final String REG_INVITE_COOLDOWN = "mesync:reg:invite:cooldown";
    private static final String REG_NONCE = "mesync:reg:nonce";
    private static final String AUTH_DEVICE_REVOKED = "mesync:auth:revoked";
    private static final String AUTH_RATE_LIMIT = "mesync:auth:rate";
    private static final String AUTH_NONCE = "mesync:auth:nonce";

    public static String registrationRateLimitKey(UUID authId) {
        return REG_RATE_LIMIT + ":" + authId;
    }

    public static String registrationInviteCooldownKey(UUID authId) {
        return REG_INVITE_COOLDOWN + ":" + authId;
    }

    public static String registrationInviteKey(UUID authId, UUID invite) {
        return REG_INVITE + ":" + authId + ":" + invite;
    }

    public static String registrationNonceKey(UUID authId) {
        return REG_NONCE + ":" + authId;
    }

    public static String authDeviceRevokedKey(UUID authId) {
        return AUTH_DEVICE_REVOKED + ":" + authId;
    }

    public static String authRateLimitKey(UUID authId) {
        return AUTH_RATE_LIMIT + ":" + authId;
    }

    public static String authNonceKey(UUID authId) {
        return AUTH_NONCE + ":" + authId;
    }

}
