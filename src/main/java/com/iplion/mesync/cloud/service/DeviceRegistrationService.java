package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.infrastructure.redis.RedisKeys;
import com.iplion.mesync.cloud.infrastructure.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceRegistrationVerificationData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.JwtUtils;
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
    private final SignatureVerificationService signatureVerificationService;

    public DeviceInviteResponseDto saveInviteToken(Jwt jwt, DeviceInviteRequestDto request) {
        UUID authId = JwtUtils.extractSubjectUuid(jwt);

        Instant expiresAt = invitationService.createInvite(
            authId,
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
        UUID authId = jwtUserData.id();
        DeviceType jwtDeviceType = DeviceType.fromClientId(jwtUserData.clientId());

        enforceRegistrationRateLimit(authId);

        boolean hasActiveDevices = deviceRepository.existsActiveByUserAuthId(authId);

        DeviceType deviceType = resolveDeviceType(
            jwtDeviceType,
            request.deviceType(),
            hasActiveDevices
        );

        byte[] decodedPublicKey = devicePublicKeyService.decodePublicKey(request.base64PublicKey());

        try {
            signatureVerificationService.deviceRegistrationVerify(new DeviceRegistrationVerificationData(
                devicePublicKeyService.createPublicKey(decodedPublicKey),
                request.name(),
                jwtDeviceType,
                request.base64PublicKey(),
                request.inviteToken(),
                request.base64Signature()
            ));
        } catch (CryptoException e) {
            throw DeviceRegistrationException.invalidSignature(authId, e);
        }

        String encryptedMasterKey = resolveEncryptedMasterKey(
            hasActiveDevices,
            request.inviteToken(),
            authId,
            jwtDeviceType
        );

        User user = userService.syncOrCreateUser(
            authId,
            jwtUserData.email(),
            jwtUserData.emailVerified()
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
            device.getName(),
            encryptedMasterKey
        );
    }

    private String resolveEncryptedMasterKey(
        boolean hasDevices,
        UUID inviteToken,
        UUID authId,
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
            authId,
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
        device.setLastActiveAt(now);

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

    public void saveWithRetry(Device device) {
        final int attempts = 3;
        final String baseName = device.getName();

        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                deviceRepository.save(device);

                return;
            } catch (DataIntegrityViolationException e) {
                if (attempt == attempts) {
                    throw DeviceRegistrationException.saveFailed(e);
                }
                if (attempt == 1) {
                    device.setName(baseName + "-" + device.getDeviceType().name().toLowerCase());
                }
                if (attempt > 1) {
                    device.setName(generateDeviceName(baseName));
                }
            }
        }
    }

    private String generateDeviceName(String baseName) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        return baseName + "-" + suffix;
    }

    public void enforceRegistrationRateLimit(UUID authId) {
        long attemptCount = redisSecurityStore.incrementWithTtl(
            RedisKeys.registrationRateLimitKey(authId),
            props.registrationTtl()
        );

        if (attemptCount > props.registrationAttempts()) {
            throw DeviceRegistrationException.rateLimit();
        }
    }
}
