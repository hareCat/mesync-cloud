package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.DeviceInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
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
public class DeviceService {
    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final RegistrationService registrationService;
    private final DevicePublicKeyService devicePublicKeyService;

    public DeviceInviteResponseDto saveInviteToken(Jwt jwt, DeviceInviteRequestDto request) {
        UUID keycloakSub = JwtUtils.extractSubjectUuid(jwt);

        Instant expiresAt = registrationService.createInvite(
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

        registrationService.enforceRegistrationRateLimit(keycloakSub);

        User user = userService.syncOrCreateUser(
            keycloakSub,
            jwtUserData.email(),
            jwtUserData.isEmailVerified()
        );

        boolean hasDevices = deviceRepository.existsActiveByUser(user);
        if (hasDevices && request.inviteToken() == null) {
            throw DeviceRegistrationException.invalidInvite(
                "Missing invite token for additional device"
            );
        }

        DeviceType deviceType = DeviceType.fromClientId(jwtUserData.clientId());
        if (!hasDevices && deviceType != request.deviceType()) {
            throw DeviceRegistrationException.firstDeviceType();
        }

        verifySignature(request, keycloakSub);

        UUID publicId = UUID.randomUUID();

        String deviceName = request.name();

        Map<String, String> extras = request.extras();

        byte[] publicKey = devicePublicKeyService.decodePublicKey(request.base64PublicKey());

        Instant now = Instant.now();

        Device device = new Device();
        device.setPublicId(publicId);
        device.setName(deviceName);
        device.setExtras(extras == null ? new HashMap<>() : new HashMap<>(extras));
        device.setPublicKey(publicKey);
        device.setUser(user);
        device.setDeviceType(deviceType);
        device.setKeyCreatedAt(now);
        device.setLastSeenAt(now);

        for (int i = 0; i < 3; i++) {
            try {
                deviceRepository.save(device);
                break;
            } catch (DataIntegrityViolationException e) {
                if (i == 2) {
                    throw DeviceRegistrationException.saveFailed(e);
                }
                device.setName(generateDeviceName(request.name()));
            }
        }

        String encodedMasterKey = hasDevices
            ? registrationService.consumeInviteAndGetEncryptedMasterKey(
            user.getKeycloakSub(),
            request.deviceType(),
            request.inviteToken()
        )
            : null;

        return new DeviceRegisterResponseDto(
            publicId,
            encodedMasterKey
        );
    }

    private void verifySignature(DeviceRegisterRequestDto request, UUID userId) {
        boolean valid = Ed25519SignatureVerifier.verify(
            devicePublicKeyService.createPublicKeyFromBase64(request.base64PublicKey()),
            DeviceRegistrationSignaturePayloadBuilder.build(request),
            request.base64Signature()
        );

        if (!valid) {
            throw DeviceRegistrationException.invalidSignature(userId);
        }
    }

    private String generateDeviceName(String baseName) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        return baseName + "-" + suffix;
    }
}
