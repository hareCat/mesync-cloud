package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.RedisOperationException;
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
public class InvitationService {
    private static final String LOCK_VALUE = "1";

    private final RedisSecurityStore redisSecurityStore;
    private final RegistrationProperties props;

    public Instant createInvite(UUID authId, UUID inviteToken, String encryptedMaster, DeviceType deviceType) {
        Duration cooldown = props.inviteCooldown();
        Duration ttl = props.inviteTtl();

        try {
            if (!redisSecurityStore.setIfAbsent(
                RedisKeys.registrationInviteCooldownKey(authId),
                LOCK_VALUE,
                cooldown)
            ) {
                throw DeviceRegistrationException.cooldownDelay(cooldown);
            }

            redisSecurityStore.set(
                RedisKeys.registrationInviteKey(authId, inviteToken),
                new DeviceInviteData(
                    encryptedMaster,
                    deviceType
                ),
                ttl
            );
        } catch (RedisOperationException e) {
            throw DeviceRegistrationException.redisSetValueError(authId, e);
        }

        return Instant.now().plus(ttl);
    }

    public String consumeInviteAndGetEncryptedMasterKey(UUID authId, DeviceType deviceType, UUID inviteToken) {
        DeviceInviteData deviceInviteData;
        try {
            deviceInviteData = redisSecurityStore.getAndDelete(
                RedisKeys.registrationInviteKey(authId, inviteToken),
                DeviceInviteData.class
            );
        } catch (RedisOperationException e) {
            throw DeviceRegistrationException.redisSetValueError(authId, e);
        }

        if (deviceInviteData == null) {
            throw DeviceRegistrationException.invalidInvite("Invite token expired. authId=" + authId);
        }

        if (deviceInviteData.deviceType() != deviceType) {
            throw DeviceRegistrationException.deviceTypeMismatch(
                String.format(
                    "Device type mismatch. authId=%s, JwtDeviceType=%s InviteDeviceType=%s",
                    authId,
                    deviceType.name(),
                    deviceInviteData.deviceType().name()
                )
            );
        }

        return deviceInviteData.encryptedMasterKey();
    }
}
