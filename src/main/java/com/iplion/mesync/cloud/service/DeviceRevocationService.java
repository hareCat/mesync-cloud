package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.controller.dto.device.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.device.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.error.api.DeviceAlreadyRevokedException;
import com.iplion.mesync.cloud.error.api.DeviceNotFoundException;
import com.iplion.mesync.cloud.event.DeviceRevokedEvent;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.request.DeviceRevokeAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.service.support.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceRevocationService {
    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final AuthPipelineService authPipelineService;
    private final Cache<UUID, DeviceAuthData> deviceAuthDataCache;
    private final ApplicationEventPublisher eventPublisher;
    private final UserService userService;

    @Transactional
    public DeviceRevokeResponseDto revokeDevice(DeviceRevokeRequestDto request) {
        AuthData authData = authPipelineService.verifyDeviceManagerRequest(DeviceRevokeAuthRequest.from(request));

        Device targetDevice = deviceRepository.findByUserIdAndPublicId(
                authData.userAuthData().id(),
                request.targetDevicePublicId()
            )
            .orElseThrow(() -> new DeviceNotFoundException(String.format(
                "Revoking device not found. targetDevicePublicId: %s",
                request.targetDevicePublicId()
            )));

        if (targetDevice.getRevokedAt() != null) {
            throw new DeviceAlreadyRevokedException(
                request.targetDevicePublicId()
            );
        }

        deviceAuthDataCache.invalidate(request.targetDevicePublicId());

        Instant revokedAt = Instant.now();
        targetDevice.setRevokedAt(revokedAt);
        deviceRepository.save(targetDevice);

        eventPublisher.publishEvent(new DeviceRevokedEvent(request.targetDevicePublicId()));

        if (request.rotateMasterKey()) {
            userService.updateMasterKeyVersion(
                userRepository.getReferenceById(authData.userAuthData().id()),
                request.deviceMasterKeyVersion()
            );
        }

        return new DeviceRevokeResponseDto(targetDevice.getPublicId(), revokedAt);
    }

}
