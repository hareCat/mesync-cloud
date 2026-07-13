package com.iplion.mesync.cloud.service.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DeviceServiceTest extends BaseUnitTest {
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
    void saveWithRetry_shouldThrowExceptionWithSaveFailedThreeTimes() throws Exception {
        Device device = TestModelFactory.device(TestModelFactory.user());

        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0);

        assertThatThrownBy(() -> deviceService.saveWithRetry(device))
            .isInstanceOf(DeviceException.class);

        verify(deviceRepository, times(3)).trySave(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void saveWithRetry_shouldSaveDeviceWithNewNameWithDeviceType() throws Exception {
        Device device = TestModelFactory.device(TestModelFactory.user());
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
        assertThat(names.get(1)).isEqualTo(generatedDeviceName);
    }

    @Test
    void saveWithRetry_shouldSaveDeviceWithNewRandomName() throws Exception {
        Device device = TestModelFactory.device(TestModelFactory.user());
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

}
