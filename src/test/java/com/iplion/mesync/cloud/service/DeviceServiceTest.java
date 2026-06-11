package com.iplion.mesync.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceServiceTest {
    @Mock
    private DeviceRepository deviceRepository;

    private DeviceService deviceService;

    @BeforeEach
    void setUp() {
        deviceService = new DeviceService(
            deviceRepository,
            new ObjectMapper()
        );
    }

    @Test
    void saveWithRetry_shouldThrowExceptionWithSaveFailedThreeTimes() {
        Device device = testDevice();

        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0);

        assertThatThrownBy(() -> deviceService.saveWithRetry(device))
            .isInstanceOf(DeviceException.class);

        verify(deviceRepository, times(3)).trySave(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void saveWithRetry_shouldSaveDeviceWithNewNameWithDeviceType() {
        Device device = testDevice();
        String deviceName = device.getName();

        String generatedDeviceName = device.getName() + "-" + device.getDeviceType().name().toLowerCase();

        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)
            .thenReturn(1);

        deviceService.saveWithRetry(device);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(deviceRepository, times(2)).trySave(
            any(), any(), any(),
            captor.capture(),
            any(), any(), any(), any()
        );
        List<String> names = captor.getAllValues();

        assertThat(names.get(0)).isEqualTo(deviceName);
        assertThat(names.get(1))
            .isEqualTo(generatedDeviceName);
    }

    @Test
    void saveWithRetry_shouldSaveDeviceWithNewRandomName() {
        Device device = testDevice();
        String deviceName = device.getName();

        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)
            .thenReturn(0)
            .thenReturn(1);

        deviceService.saveWithRetry(device);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(deviceRepository, times(3)).trySave(
            any(), any(), any(),
            captor.capture(),
            any(), any(), any(), any()
        );
        List<String> names = captor.getAllValues();

        assertThat(names.get(2))
            .isNotEqualTo(deviceName)
            .startsWith(deviceName)
            .hasSizeGreaterThan(deviceName.length());
    }

    // helpers

    private Device testDevice() {
        User user = new User();
        user.setAuthId(UUID.randomUUID());

        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setUser(user);
        device.setName("test name");
        device.setDeviceType(DeviceType.MOBILE);
        device.setPublicKeyBytes("pk".getBytes());
        device.setExtras(Map.of());

        return device;
    }

}
