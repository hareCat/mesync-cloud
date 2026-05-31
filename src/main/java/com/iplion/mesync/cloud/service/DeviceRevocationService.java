package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.error.DeviceNotFoundException;
import com.iplion.mesync.cloud.error.DeviceRevokeException;
import com.iplion.mesync.cloud.event.DeviceRevokedEvent;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
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
    private final SecurityService securityService;
    private final Cache<UUID, DeviceAuthData> deviceAuthDataCache;
    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    public DeviceRevokeResponseDto revokeDevice(Jwt jwt, DeviceRevokeRequestDto request) {
        DeviceAuthData deviceAuthData = securityService.verifyDeviceManagerRequest(DeviceRevokeAuthRequest.from(jwt, request));

        Device targetDevice = deviceRepository.findByUserIdAndPublicId(deviceAuthData.userId(), request.targetDevicePublicId())
            .orElseThrow(() -> new DeviceNotFoundException(String.format(
                "Revoking device not found. userId: %d, deviceId: %d, targetDevicePublicId: %s",
                deviceAuthData.userId(),
                deviceAuthData.id(),
                request.targetDevicePublicId()
            )));

        if (targetDevice.getRevokedAt() != null) {
            throw new DeviceRevokeException(deviceAuthData.userId(), deviceAuthData.id(), request.targetDevicePublicId());
        }

        deviceAuthDataCache.invalidate(request.targetDevicePublicId());

        targetDevice.setRevokedAt(Instant.now());
        deviceRepository.save(targetDevice);

        eventPublisher.publishEvent(new DeviceRevokedEvent(request.targetDevicePublicId()));

        return new DeviceRevokeResponseDto(targetDevice.getPublicId());
    }

}
