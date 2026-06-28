package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyResponseDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.AuthService;
import com.iplion.mesync.cloud.security.SecurityContextUtils;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.StoreInviteAuthRequest;
import com.iplion.mesync.cloud.security.auth.StoreMasterKeyAuthRequest;
import com.iplion.mesync.cloud.security.auth.StorePublicKeysAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

//TODO change security deviceType check to roles check and remove DeviceType.MANAGER
@Service
@RequiredArgsConstructor
@Slf4j
public class DeviceRegistrationService {
    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final InvitationService invitationService;
    private final DeviceService deviceService;
    private final AuthService authService;
    private final KeySignatureService keySignatureService;

    public StoreInviteResponseDto storeInviteToken(StoreInviteRequestDto request) {
        authService.verifyDeviceManagerRequest(StoreInviteAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        if (authData.userAuthData().keyVersion() > request.keyVersion()) {
            throw DeviceRegistrationException.masterKeyVersionMismatch(
                authData.userAuthData().keyVersion(),
                request.keyVersion()
            );
        }

        Instant expiresAt = invitationService.createInvite(
            authData.userAuthData().authId(),
            request.inviteToken(),
            request.deviceType()
        );

        return new StoreInviteResponseDto(
            expiresAt
        );
    }

    public StorePublicKeysResponseDto storePublicKeys(StorePublicKeysRequestDto request) {
        authService.verifyUnregisteredDeviceRequest(StorePublicKeysAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        Instant expiresAt = invitationService.storePublicKeys(
            authData.userAuthData().authId(),
            request.inviteToken(),
            request.base64EncryptionPublicKey(),
            request.base64SigningPublicKey()
        );

        return new StorePublicKeysResponseDto(
            expiresAt
        );
    }

    public StoreMasterKeyResponseDto storeMasterKey(StoreMasterKeyRequestDto request) {
        authService.verifyDeviceManagerRequest(StoreMasterKeyAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        Instant expiresAt = invitationService.storeMasterKey(
            authData.userAuthData().authId(),
            request.inviteToken(),
            request.base64EncryptedMasterKey(),
            request.keyVersion()
        );

        return new StoreMasterKeyResponseDto(
            expiresAt
        );
    }

    @Transactional
    public DeviceRegisterResponseDto registerDevice(DeviceRegisterRequestDto request) {
        JwtUserData jwtUserData = authService.verifyUnregisteredDeviceRequest(RegistrationAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        UUID authId = authData.userAuthData().authId();
        DeviceType deviceType = authData.deviceAuthData().deviceType();
        String inviteToken = request.inviteToken();

        boolean hasActiveDevices = deviceRepository.existsActiveByUserAuthId(authId);

        if (!hasActiveDevices && deviceType != DeviceType.MOBILE) {
            throw DeviceRegistrationException.firstDeviceType();
        }

        String encryptedMasterKey = null;
        Integer keyVersion = null;
        DeviceInviteData deviceInviteData = null;

        if (hasActiveDevices) {
            if (inviteToken == null || inviteToken.isBlank()) {
                throw DeviceRegistrationException.invalidInvite(
                    "Missing invite token for additional device."
                );
            }

            deviceInviteData = invitationService.getDeviceInviteData(authId, inviteToken);

            if (deviceInviteData.getDeviceType() != authData.deviceAuthData().deviceType()) {
                throw new InvalidDeviceTypeException("JWT device type is different from invite device");
            }

            if (!Objects.equals(deviceInviteData.getBase64SigningPublicKey(), request.base64PublicKey())) {
                throw DeviceRegistrationException.invalidInvite(
                    "Registration public key does not match invite public key."
                );
            }

            if (deviceInviteData.getBase64EncryptedMasterKey() == null || deviceInviteData.getKeyVersion() == null) {
                throw DeviceRegistrationException.invalidInvite(
                    "Master key is not ready for invite."
                );
            }

            encryptedMasterKey = deviceInviteData.getBase64EncryptedMasterKey();
            keyVersion = deviceInviteData.getKeyVersion();

            invitationService.lockDeviceInviteData(authId, inviteToken);
        }

        User user;
        try {
            user = userService.syncOrCreateUser(
                authId,
                jwtUserData.email(),
                jwtUserData.emailVerified()
            );
        } catch (IllegalStateException e) {
            throw DeviceRegistrationException.userSaveFailed(e);
        }

        Device device = buildDevice(
            user,
            deviceType,
            keySignatureService.extractPublicKeyBytes(authData.deviceAuthData().publicKey()),
            request.deviceName(),
            request.extras()
        );

        try {
            deviceService.saveWithRetry(device);
        } catch (DeviceException e) {
            throw DeviceRegistrationException.saveFailed(e);
        }

        if (deviceInviteData != null && !invitationService.deleteDeviceInviteData(authId, inviteToken)) {
            throw DeviceRegistrationException.inviteDeleteFailed();
        }

        return new DeviceRegisterResponseDto(
            device.getPublicId(),
            device.getName(),
            encryptedMasterKey,
            keyVersion == null ? user.getKeyVersion() : keyVersion
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
