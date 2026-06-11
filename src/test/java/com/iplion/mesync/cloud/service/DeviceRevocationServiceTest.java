package com.iplion.mesync.cloud.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.api.DeviceAlreadyRevokedException;
import com.iplion.mesync.cloud.error.api.DeviceNotFoundException;
import com.iplion.mesync.cloud.event.DeviceRevokedEvent;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.AuthService;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceRevocationServiceTest {
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserRepository userRepository;
    @Mock
    AuthService authService;
    @Mock
    UserService userService;
    @Mock
    ApplicationEventPublisher eventPublisher;
    @Mock
    Cache<UUID, DeviceAuthData> deviceAuthDataCache;

    @InjectMocks
    DeviceRevocationService deviceRevocationService;

    @Test
    void revokeDevice_shouldRevokeDeviceAndRotateMasterKeyVersion() throws Exception {
        AuthData authData = TestModelFactory.authContext();
        User user = TestModelFactory.user();
        Device targetDevice = TestModelFactory.device(user);
        int deviceMasterKeyVersion = 2;
        var request = deviceRevokeRequestDto(targetDevice.getPublicId(), true, deviceMasterKeyVersion);

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authData);
        when(deviceRepository.findByUserIdAndPublicId(any(), any())).thenReturn(Optional.of(targetDevice));
        when(userRepository.getReferenceById(authData.userAuthData().id())).thenReturn(user);

        DeviceRevokeResponseDto responseDto = deviceRevocationService.revokeDevice(request);

        assertThat(targetDevice.getRevokedAt()).isNotNull();

        verify(deviceRepository).findByUserIdAndPublicId(
            eq(authData.userAuthData().id()),
            eq(request.targetDevicePublicId())
        );
        verify(deviceAuthDataCache).invalidate(eq(request.targetDevicePublicId()));
        verify(deviceRepository).save(eq(targetDevice));

        ArgumentCaptor<DeviceRevokedEvent> captor = ArgumentCaptor.forClass(DeviceRevokedEvent.class);
        verify(eventPublisher, times(1)).publishEvent(captor.capture());
        assertThat(captor.getValue().targetDevicePublicId()).isEqualTo(request.targetDevicePublicId());

        verify(userService).updateMasterKeyVersion(eq(user), eq(deviceMasterKeyVersion));

        assertThat(responseDto.revokedDevicePublicId()).isEqualTo(request.targetDevicePublicId());
        assertThat(responseDto.revokedAt()).isNotNull();
    }

    @Test
    void revokeDevice_shouldRevokeDeviceWithoutRotateMasterKeyVersion() throws Exception {
        AuthData authData = TestModelFactory.authContext();
        Device targetDevice = TestModelFactory.device(TestModelFactory.user());
        int deviceMasterKeyVersion = 2;
        var request = deviceRevokeRequestDto(targetDevice.getPublicId(), false, deviceMasterKeyVersion);

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authData);
        when(deviceRepository.findByUserIdAndPublicId(any(), any())).thenReturn(Optional.of(targetDevice));

        DeviceRevokeResponseDto responseDto = deviceRevocationService.revokeDevice(request);

        assertThat(targetDevice.getRevokedAt()).isNotNull();

        verify(deviceRepository).findByUserIdAndPublicId(
            eq(authData.userAuthData().id()),
            eq(request.targetDevicePublicId())
        );
        verify(deviceAuthDataCache).invalidate(eq(request.targetDevicePublicId()));
        verify(deviceRepository).save(eq(targetDevice));
        verify(eventPublisher, times(1)).publishEvent(any(DeviceRevokedEvent.class));
        verifyNoInteractions(userRepository);
        verifyNoInteractions(userService);

        assertThat(responseDto.revokedDevicePublicId()).isEqualTo(request.targetDevicePublicId());
        assertThat(responseDto.revokedAt()).isNotNull();
    }

    @Test
    void revokeDevice_shouldThrow_whenRevokingDeviceNotFound() throws Exception {
        AuthData authData = TestModelFactory.authContext();
        Device targetDevice = TestModelFactory.device(TestModelFactory.user());
        var request = deviceRevokeRequestDto(targetDevice.getPublicId());

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authData);
        when(deviceRepository.findByUserIdAndPublicId(any(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> deviceRevocationService.revokeDevice(request))
            .isInstanceOf(DeviceNotFoundException.class)
            .hasMessageContaining("found");

        verifyNoInteractions(deviceAuthDataCache);
    }

    @Test
    void revokeDevice_shouldThrow_whenDeviceAlreadyRevoked() throws Exception {
        AuthData authData = TestModelFactory.authContext();

        Device targetDevice = TestModelFactory.device(TestModelFactory.user());
        targetDevice.setRevokedAt(Instant.now());

        var request = deviceRevokeRequestDto(targetDevice.getPublicId());

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authData);
        when(deviceRepository.findByUserIdAndPublicId(any(), any())).thenReturn(Optional.of(targetDevice));

        assertThatThrownBy(() -> deviceRevocationService.revokeDevice(request))
            .isInstanceOf(DeviceAlreadyRevokedException.class)
            .hasMessageContaining("already");

        verifyNoInteractions(deviceAuthDataCache);
    }

    // --------------------- helpers ---------------------

    public static DeviceRevokeRequestDto deviceRevokeRequestDto(UUID targetDevicePublicId) {
        return deviceRevokeRequestDto(targetDevicePublicId, false, 1);
    }

    public static DeviceRevokeRequestDto deviceRevokeRequestDto(
        UUID targetDevicePublicId,
        boolean rotateMasterKeyVersion,
        int keyVersion
    ) {
        return new DeviceRevokeRequestDto(
            UUID.randomUUID(),
            targetDevicePublicId,
            rotateMasterKeyVersion,
            keyVersion,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
