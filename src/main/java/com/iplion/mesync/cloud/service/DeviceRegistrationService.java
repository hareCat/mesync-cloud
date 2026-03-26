package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.infrastructure.redis.RedisKeys;
import com.iplion.mesync.cloud.infrastructure.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.JwtUtils;
import com.iplion.mesync.cloud.security.crypto.DeviceRegistrationSignaturePayloadBuilder;
import com.iplion.mesync.cloud.security.crypto.Ed25519SignatureVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceRegistrationService {
    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final InvitationService invitationService;
    private final DevicePublicKeyService devicePublicKeyService;
    private final RedisSecurityStore redisSecurityStore;
    private final RegistrationProperties props;

    public DeviceInviteResponseDto saveInviteToken(Jwt jwt, DeviceInviteRequestDto request) {
        UUID keycloakSub = JwtUtils.extractSubjectUuid(jwt);

        Instant expiresAt = invitationService.createInvite(
            keycloakSub,
            request.inviteToken(),
            request.encryptedMasterKey(),
            request.deviceType()
        );

        return new DeviceInviteResponseDto(
            expiresAt
        );
    }

    @Transactional
    public DeviceRegisterResponseDto registerDevice(Jwt jwt, DeviceRegisterRequestDto request) {
        JwtUserData jwtUserData = JwtUtils.extractUserData(jwt);
        UUID keycloakSub = jwtUserData.id();
        DeviceType jwtDeviceType = DeviceType.fromClientId(jwtUserData.clientId());

        enforceRegistrationRateLimit(keycloakSub);

        User user = userService.syncOrCreateUser(
            keycloakSub,
            jwtUserData.email(),
            jwtUserData.emailVerified()
        );

        boolean hasDevices = deviceRepository.existsActiveByUser(user);

        DeviceType deviceType = resolveDeviceType(
            jwtDeviceType,
            request.deviceType(),
            hasDevices
        );

        String encryptedMasterKey = resolveEncryptedMasterKey(
            hasDevices,
            request.inviteToken(),
            keycloakSub,
            jwtDeviceType
        );


        byte[] decodedPublicKey = devicePublicKeyService.decodePublicKey(request.base64PublicKey());

        verifySignature(
            decodedPublicKey,
            DeviceRegistrationSignaturePayloadBuilder.build(request),
            request.base64Signature(),
            keycloakSub
        );

        Device device = buildDevice(
            user,
            deviceType,
            decodedPublicKey,
            request.name(),
            request.extras()
        );

        saveWithRetry(device);

        return new DeviceRegisterResponseDto(
            device.getPublicId(),
            encryptedMasterKey
        );
    }

    private String resolveEncryptedMasterKey(
        boolean hasDevices,
        UUID inviteToken,
        UUID keycloakSub,
        DeviceType jwtDeviceType
    ) {
        if (!hasDevices) {
            return null;
        }

        if (inviteToken == null) {
            throw DeviceRegistrationException.invalidInvite(
                "Missing invite token for additional device"
            );
        }

        return invitationService.consumeInviteAndGetEncryptedMasterKey(
            keycloakSub,
            jwtDeviceType,
            inviteToken
        );
    }

    private Device buildDevice(
        User user,
        DeviceType deviceType,
        byte[] decodedPublicKey,
        String deviceName,
        Map<String, String> extras
    ) {
        Instant now = Instant.now();

        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setName(deviceName);
        device.setExtras(extras == null ? new HashMap<>() : new HashMap<>(extras));
        device.setPublicKey(decodedPublicKey);
        device.setUser(user);
        device.setDeviceType(deviceType);
        device.setKeyCreatedAt(now);
        device.setLastSeenAt(now);

        return device;
    }

    private DeviceType resolveDeviceType(
        DeviceType jwtDeviceType,
        DeviceType requestDeviceType,
        boolean hasDevices
    ) {
        if (jwtDeviceType != requestDeviceType) {
            throw DeviceRegistrationException.deviceTypeMismatch();
        }

        if (!hasDevices && jwtDeviceType != DeviceType.MOBILE) {
            throw DeviceRegistrationException.firstDeviceType();
        }

        return jwtDeviceType;
    }

    private void saveWithRetry(Device device) {
        final int attempts = 2;
        final String baseName = device.getName();

        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                deviceRepository.save(device);

                return;
            } catch (DataIntegrityViolationException e) {
                if (attempt == attempts) {
                    throw DeviceRegistrationException.saveFailed(e);
                }
                device.setName(generateDeviceName(baseName));
            }
        }
    }

    private void verifySignature(
        byte[] decodedPublicKey,
        byte[] payloadBytes,
        String base64Signature,
        UUID userId
    ) {
        boolean valid = Ed25519SignatureVerifier.verify(
            devicePublicKeyService.createPublicKey(decodedPublicKey),
            payloadBytes,
            base64Signature
        );

        if (!valid) {
            throw DeviceRegistrationException.invalidSignature(userId);
        }
    }

    private String generateDeviceName(String baseName) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        return baseName + "-" + suffix;
    }

    public void enforceRegistrationRateLimit(UUID sub) {
        Long attemptCount = redisSecurityStore.incrementWithTtl(
            RedisKeys.registrationRateLimitKey(sub),
            props.registrationTtl()
        );

        if (attemptCount > props.registrationAttempts()) {
            throw DeviceRegistrationException.rateLimit();
        }
    }


}
