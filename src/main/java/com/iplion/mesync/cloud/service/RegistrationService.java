package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.infrastructure.redis.RedisKeys;
import com.iplion.mesync.cloud.infrastructure.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RegistrationService {
    private static final String LOCK_VALUE = "1";

    private final RedisSecurityStore redisSecurityStore;
    private final RegistrationProperties props;

    public void enforceRegistrationRateLimit(UUID sub) {
        Long attemptCount = redisSecurityStore.incrementWithTtl(
            RedisKeys.registrationRateLimitKey(sub),
            props.registrationTtl()
        );

        if (attemptCount == null || attemptCount > props.registrationAttempts()) {
            throw DeviceRegistrationException.rateLimit();
        }
    }

    public Instant createInvite(UUID sub, UUID inviteToken, String encryptedMaster, DeviceType deviceType) {
        Duration cooldown = props.inviteCooldown();
        if (!redisSecurityStore.setIfAbsent(
            RedisKeys.registrationInviteCooldownKey(sub),
            LOCK_VALUE,
            cooldown)
        ) {
            throw DeviceRegistrationException.cooldownDelay(cooldown);
        }

        Duration ttl = props.inviteTtl();
        redisSecurityStore.set(
            RedisKeys.registrationInviteKey(sub, inviteToken),
            new DeviceInviteData(
                encryptedMaster,
                deviceType
            ),
            ttl
        );

        return Instant.now().plus(ttl);
    }

    public String consumeInviteAndGetEncryptedMasterKey(UUID sub, DeviceType deviceType, UUID inviteToken) {
        DeviceInviteData deviceInviteData = redisSecurityStore.getAndDelete(
            RedisKeys.registrationInviteKey(sub, inviteToken),
            DeviceInviteData.class
        );

        if (deviceInviteData == null) {
            throw DeviceRegistrationException.invalidInvite("Invite token expired. userId=" + sub);
        }

        if (!deviceInviteData.deviceType().equals(deviceType)) {
            throw DeviceRegistrationException.invalidInvite(
                String.format("Invalid device type into invite. userId=%s, deviceType=%s", sub, deviceType.name())
            );
        }

        return deviceInviteData.encryptedMasterKey();
    }
}
