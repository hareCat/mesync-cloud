package com.iplion.mesync.cloud.security.cache;

import java.util.UUID;

public final class RedisKeys {
    private static final String REG_RATE_LIMIT = "mesync:reg:rate";
    private static final String REG_INVITE = "mesync:reg:invite";
    private static final String REG_INVITE_COOLDOWN = "mesync:reg:invite:cooldown";
    private static final String REG_NONCE = "mesync:reg:nonce";
    private static final String AUTH_DEVICE_REVOKED = "mesync:auth:revoked";
    private static final String AUTH_RATE_LIMIT = "mesync:auth:rate";
    private static final String AUTH_NONCE = "mesync:auth:nonce";

    public static String registrationRateLimitKey(UUID id) {
        return REG_RATE_LIMIT + ":" + id;
    }

    public static String registrationInviteCooldownKey(UUID id) {
        return REG_INVITE_COOLDOWN + ":" + id;
    }

    public static String registrationInviteKey(UUID id, UUID invite) {
        return REG_INVITE + ":" + id + ":" + invite;
    }

    public static String registrationNonceKey(UUID id, UUID nonce) {
        return REG_NONCE + ":" + id + ":" + nonce;
    }

    public static String authDeviceRevokedKey(UUID id) {
        return AUTH_DEVICE_REVOKED + ":" + id;
    }

    public static String authRateLimitKey(UUID id) {
        return AUTH_RATE_LIMIT + ":" + id;
    }

    public static String authNonceKey(UUID id, UUID nonce) {
        return AUTH_NONCE + ":" + id + ":" + nonce;
    }

}
