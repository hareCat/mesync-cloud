package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
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
    private final AppProperties props;

    public Instant createInvite(
        UUID authId,
        String inviteToken,
        DeviceType deviceType
    ) {
        String redisCooldownKey = RedisKeys.registrationInviteCooldownKey(authId);
        cooldownCheck(redisCooldownKey);

        DeviceInviteData inviteData = new DeviceInviteData();
        inviteData.setDeviceType(deviceType);

        return setDeviceInviteData(authId, inviteToken, inviteData);
    }

    public Instant storePublicKeys(
        UUID authId,
        String inviteToken,
        String base64EncryptionPublicKey,
        String base64SigningPublicKey
    ) {
        String redisCooldownKey = RedisKeys.registrationPublicKeyCooldownKey(authId);
        cooldownCheck(redisCooldownKey);

        DeviceInviteData inviteData = getDeviceInviteData(authId, inviteToken);

        inviteData.setBase64EncryptionPublicKey(base64EncryptionPublicKey);
        inviteData.setBase64SigningPublicKey(base64SigningPublicKey);

        return setDeviceInviteData(authId, inviteToken, inviteData);
    }

    public Instant storeMasterKey(
        UUID authId,
        String inviteToken,
        String base64EncryptedMasterKey,
        int masterKeyVersion
    ) {
        String redisCooldownKey = RedisKeys.registrationMasterKeyCooldownKey(authId);
        cooldownCheck(redisCooldownKey);

        DeviceInviteData inviteData = getDeviceInviteData(authId, inviteToken);

        if (inviteData.getBase64EncryptionPublicKey() == null || inviteData.getBase64SigningPublicKey() == null) {
            throw DeviceRegistrationException.invalidInvite(
                "Public keys are not ready for invite."
            );
        }

        inviteData.setBase64EncryptedMasterKey(base64EncryptedMasterKey);
        inviteData.setKeyVersion(masterKeyVersion);

        return setDeviceInviteData(authId, inviteToken, inviteData);
    }

    public DeviceInviteData getDeviceInviteData(UUID authId, String inviteToken) {
        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(authId, inviteToken),
            DeviceInviteData.class
        );

        if (inviteData == null) {
            throw DeviceRegistrationException.invalidInvite("Invite token expired.");
        }

        return inviteData;
    }

    public void lockDeviceInviteData(UUID authId, String inviteToken) {
        cooldownCheck(RedisKeys.registrationLastStepCooldownKey(authId, inviteToken));
    }

    public boolean deleteDeviceInviteData(UUID authId, String inviteToken) {
        return redisSecurityStore.delete(RedisKeys.registrationInviteKey(authId, inviteToken));
    }

    private Instant setDeviceInviteData(UUID authId, String inviteToken, DeviceInviteData inviteData) {
        Duration ttl = props.registration().inviteTtl();

        redisSecurityStore.set(
            RedisKeys.registrationInviteKey(authId, inviteToken),
            inviteData,
            ttl
        );

        return Instant.now().plus(ttl);
    }

    private void cooldownCheck(String redisCooldownKey) {
        Duration cooldown = props.registration().inviteCooldown();

        if (!redisSecurityStore.setIfAbsent(
            redisCooldownKey,
            LOCK_VALUE,
            cooldown)
        ) {
            throw DeviceRegistrationException.cooldownDelay(cooldown);
        }
    }

}
