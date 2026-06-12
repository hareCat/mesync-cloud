package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.AuthService;
import com.iplion.mesync.cloud.security.SecurityContextUtils;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

//TODO change security deviceType check to roles check and remove DeviceType.MANAGER
@Service
@RequiredArgsConstructor
public class DeviceRegistrationService {
    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final InvitationService invitationService;
    private final DeviceService deviceService;
    private final AuthService authService;
    private final KeySignatureService keySignatureService;

    public SaveInviteResponseDto saveInviteToken(SaveInviteRequestDto request) {
        authService.verifyDeviceManagerRequest(SaveInviteAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        if (authData.userAuthData().keyVersion() > request.keyVersion()) {
            throw DeviceRegistrationException.masterKeyVersionMismatch(
                authData.userAuthData().id(),
                authData.deviceAuthData().id(),
                authData.userAuthData().keyVersion(),
                request.keyVersion()
            );
        }

        Instant expiresAt = invitationService.createInvite(
            authData.userAuthData().authId(),
            request.inviteToken(),
            request.encryptedMasterKey(),
            request.keyVersion(),
            request.deviceType()
        );

        return new SaveInviteResponseDto(
            expiresAt
        );
    }

    @Transactional
    public DeviceRegisterResponseDto registerDevice(DeviceRegisterRequestDto request) {
        RegistrationAuthResult authResult = authService.verifyRegistrationRequest(
            RegistrationAuthRequest.from(request)
        );

        UUID authId = authResult.jwtUserData().authId();
        DeviceType deviceType;
        try {
            deviceType = DeviceType.fromClientId(authResult.jwtUserData().clientId());
        } catch (InvalidDeviceTypeException e) {
            throw DeviceRegistrationException.wrongRegisterData(
                String.format("Invalid jwt clientId: %s, authId: %s",
                    authResult.jwtUserData().clientId(),
                    authResult.jwtUserData().authId()
                ),
                e
            );
        }

        boolean hasActiveDevices = deviceRepository.existsActiveByUserAuthId(authId);

        if (!hasActiveDevices && deviceType != DeviceType.MOBILE) {
            throw DeviceRegistrationException.firstDeviceType(authId);
        }

        String encryptedMasterKey = null;
        Integer keyVersion = null;
        if (hasActiveDevices) {
            DeviceInviteData deviceInviteData = getInviteData(
                request.inviteToken(),
                authId,
                deviceType
            );

            encryptedMasterKey = deviceInviteData.encryptedMasterKey();
            keyVersion = deviceInviteData.keyVersion();
        }

        User user;
        try {
            user = userService.syncOrCreateUser(
                authId,
                authResult.jwtUserData().email(),
                authResult.jwtUserData().emailVerified()
            );
        } catch (IllegalStateException e) {
            throw DeviceRegistrationException.userSaveFailed(authId, e);
        }

        Device device = buildDevice(
            user,
            deviceType,
            keySignatureService.extractPublicKeyBytes(authResult.publicKey()),
            request.deviceName(),
            request.extras()
        );

        try {
            deviceService.saveWithRetry(device);
        } catch (DeviceException e) {
            throw DeviceRegistrationException.saveFailed(authId, e);
        }

        return new DeviceRegisterResponseDto(
            device.getPublicId(),
            device.getName(),
            encryptedMasterKey,
            keyVersion == null ? user.getKeyVersion() : keyVersion
        );
    }

    private DeviceInviteData getInviteData(
        UUID inviteToken,
        UUID authId,
        DeviceType deviceType
    ) {
        if (inviteToken == null) {
            throw DeviceRegistrationException.invalidInvite(
                "Missing invite token for additional device. authId: " + authId
            );
        }

        return invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            deviceType,
            inviteToken
        );
    }

    private Device buildDevice(
        User user,
        DeviceType deviceType,
        byte[] publicKeyBytes,
        String deviceName,
        Map<String, String> extras
    ) {
        Instant now = Instant.now();

        Device device = new Device();
        device.setName(deviceName);
        device.setExtras(extras == null ? new HashMap<>() : new HashMap<>(extras));
        device.setPublicKeyBytes(publicKeyBytes);
        device.setUser(user);
        device.setDeviceType(deviceType);
        device.setKeyCreatedAt(now);
        device.setLastActiveAt(now);

        return device;
    }

}
