package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.error.DeviceNotFoundException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DevicePublicKeyService {
    private final Cache<UUID, PublicKey> publicKeyCache;
    private final DeviceRepository deviceRepository;
    private final KeyFactory keyFactory;

    public PublicKey getPublicKey(UUID deviceId) {
        return publicKeyCache.get(deviceId, this::loadPublicKey);
    }

    private PublicKey loadPublicKey(UUID deviceId) {
        byte[] publicKeyBytes = deviceRepository.findActivePublicKeyByPublicId(deviceId)
            .orElseThrow(() -> new DeviceNotFoundException(deviceId));

        return createPublicKey(publicKeyBytes);
    }

    public PublicKey createPublicKey(byte[] publicKeyBytes) {
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (GeneralSecurityException e) {
            throw new InvalidPublicKeyException("Public key generation error", e);
        }
    }

    public byte[] decodePublicKey(String base64PublicKey) {
        try {
            return Base64.getDecoder().decode(base64PublicKey);
        } catch (IllegalArgumentException e) {
            throw new InvalidPublicKeyException("Can't decode base64 public key", e);
        }
    }
}
