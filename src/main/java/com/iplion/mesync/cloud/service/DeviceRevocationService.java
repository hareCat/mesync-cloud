package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.error.api.DeviceNotFoundException;
import com.iplion.mesync.cloud.error.api.DeviceAlreadyRevokedException;
import com.iplion.mesync.cloud.event.DeviceRevokedEvent;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.SecurityService;
import com.iplion.mesync.cloud.security.auth.DeviceRevokeAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceRevocationService {
    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final SecurityService securityService;
    private final Cache<UUID, DeviceAuthData> deviceAuthDataCache;
    private final ApplicationEventPublisher eventPublisher;
    private final UserService userService;

    @Transactional
    public DeviceRevokeResponseDto revokeDevice(Jwt jwt, DeviceRevokeRequestDto request) {
        DeviceAuthData deviceAuthData = securityService.verifyDeviceManagerRequest(DeviceRevokeAuthRequest.from(jwt, request));

        Device targetDevice = deviceRepository.findByUserIdAndPublicId(deviceAuthData.userId(), request.targetDevicePublicId())
            .orElseThrow(() -> new DeviceNotFoundException(String.format(
                "Revoking device not found. userId: %d, deviceId: %d, targetDevicePublicId: %s",
                deviceAuthData.userId(),
                deviceAuthData.deviceId(),
                request.targetDevicePublicId()
            )));

        if (targetDevice.getRevokedAt() != null) {
            throw new DeviceAlreadyRevokedException(deviceAuthData.userId(), deviceAuthData.deviceId(), request.targetDevicePublicId());
        }

        deviceAuthDataCache.invalidate(request.targetDevicePublicId());

        Instant revokedAt = Instant.now();
        targetDevice.setRevokedAt(revokedAt);
        deviceRepository.save(targetDevice);

        eventPublisher.publishEvent(new DeviceRevokedEvent(request.targetDevicePublicId()));

        if (request.rotateMasterKey()) {
            userService.updateMasterKeyVersion(
                userRepository.getReferenceById(deviceAuthData.userId()),
                request.deviceMasterKeyVersion()
            );
        }

        return new DeviceRevokeResponseDto(targetDevice.getPublicId(), revokedAt);
    }

}
