package com.iplion.mesync.cloud.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceService {
    private final Cache<UUID, DeviceAuthData> deviceAuthDataCache;
    private final DeviceRepository deviceRepository;
    private final KeySignatureService keySignatureService;
    private final ObjectMapper objectMapper;

    public DeviceAuthData getDeviceAuthData(UUID devicePublicId) {
        return deviceAuthDataCache.get(devicePublicId, this::loadDeviceAuthDataCache);
    }

    private DeviceAuthData loadDeviceAuthDataCache(UUID devicePublicId) {
        return deviceRepository.findAuthDataByPublicId(devicePublicId)
            .map(projection -> projection.toDeviceAuthData(keySignatureService))
            .orElseThrow(() -> new DeviceException("Device not found. devicePublicId: " + devicePublicId));
    }

    public void saveWithRetry(Device device) {
        final int attempts = 3;
        final String baseName = device.getName();

        for (int attempt = 1; attempt <= attempts; attempt++) {
            if (trySave(device)) {
                return;
            }

            if (attempt == attempts) {
                throw new DeviceException("Failed to persist device");
            }

            if (attempt == 1) {
                device.setName(baseName + "-" + device.getDeviceType().name().toLowerCase());
            }

            if (attempt > 1) {
                device.setName(generateName(baseName));
            }
        }
    }

    private boolean trySave(Device device) {
        int result = deviceRepository.trySave(
            device.getPublicId(),
            device.getUser().getId(),
            device.getDeviceType().name(),
            device.getName(),
            device.getPublicKeyBytes(),
            device.getKeyCreatedAt(),
            device.getLastActiveAt(),
            serializeExtras(device.getExtras())
        );

        return result == 1;
    }

    private String generateName(String baseName) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        return baseName + "-" + suffix;
    }

    private String serializeExtras(Map<String, String> extras) {
        try {
            return objectMapper.writeValueAsString(extras);
        } catch (JsonProcessingException e) {
            throw new DeviceException("Failed to serialize device extras");
        }
    }

}
