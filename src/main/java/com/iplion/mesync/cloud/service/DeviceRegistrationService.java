package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreMasterKeyResponseDto;
import com.iplion.mesync.cloud.controller.dto.registration.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.StorePublicKeysResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineResult;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.request.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.request.StoreInviteAuthRequest;
import com.iplion.mesync.cloud.security.request.StoreMasterKeyAuthRequest;
import com.iplion.mesync.cloud.security.request.StorePublicKeysAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.service.support.DeviceService;
import com.iplion.mesync.cloud.service.support.InvitationService;
import com.iplion.mesync.cloud.service.support.UserService;
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
    private final AuthPipelineService authPipelineService;
    private final KeySignatureService keySignatureService;

    public StoreInviteResponseDto storeInviteToken(StoreInviteRequestDto request) {
        AuthData authData = authPipelineService.verifyDeviceManagerRequest(StoreInviteAuthRequest.from(request));

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
        AuthPipelineResult authPipelineResult = authPipelineService.verifyUnregisteredDeviceRequest(
            StorePublicKeysAuthRequest.from(request)
        );
        AuthData authData = authPipelineResult.authData();

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
        AuthData authData = authPipelineService.verifyDeviceManagerRequest(StoreMasterKeyAuthRequest.from(request));

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
        AuthPipelineResult authPipelineResult = authPipelineService.verifyUnregisteredDeviceRequest(
            RegistrationAuthRequest.from(request)
        );
        JwtUserData jwtUserData = authPipelineResult.jwtUserData();
        AuthData authData = authPipelineResult.authData();

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
