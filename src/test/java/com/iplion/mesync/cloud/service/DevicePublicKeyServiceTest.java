package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.iplion.mesync.cloud.error.DeviceNotFoundException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DevicePublicKeyServiceTest {
    @Mock
    private DeviceRepository deviceRepository;

    private DevicePublicKeyService devicePublicKeyService;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        Cache<UUID, PublicKey> cache = Caffeine.newBuilder().build();
        devicePublicKeyService = new DevicePublicKeyService(cache, deviceRepository, KeyFactory.getInstance("Ed25519"));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        keyPair = generator.generateKeyPair();
    }

    @Test
    void getPublicKeyLoadsFromRepositoryAndCachesResult() {
        UUID deviceId = UUID.randomUUID();
        byte[] encodedKey = keyPair.getPublic().getEncoded();
        when(deviceRepository.findActivePublicKeyByPublicId(deviceId)).thenReturn(Optional.of(encodedKey));

        PublicKey first = devicePublicKeyService.getPublicKey(deviceId);
        PublicKey second = devicePublicKeyService.getPublicKey(deviceId);

        assertThat(first.getEncoded()).isEqualTo(encodedKey);
        assertThat(second.getEncoded()).isEqualTo(encodedKey);
        verify(deviceRepository, times(1)).findActivePublicKeyByPublicId(deviceId);
    }

    @Test
    void getPublicKeyThrowsWhenDeviceIsMissing() {
        UUID deviceId = UUID.randomUUID();
        when(deviceRepository.findActivePublicKeyByPublicId(deviceId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> devicePublicKeyService.getPublicKey(deviceId))
            .isInstanceOf(DeviceNotFoundException.class);
    }

    @Test
    void createPublicKeyFromBytesThrowsForInvalidKey() {
        assertThatThrownBy(() -> devicePublicKeyService.createPublicKey(new byte[] {1, 2, 3}))
            .isInstanceOf(InvalidPublicKeyException.class)
            .hasMessageContaining("Public key generation error");
    }

}
