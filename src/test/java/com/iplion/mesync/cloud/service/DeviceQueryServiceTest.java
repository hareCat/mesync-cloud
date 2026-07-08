package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.device.DeviceListItemDto;
import com.iplion.mesync.cloud.controller.dto.device.DeviceListRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.request.DeviceListAuthRequest;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceQueryServiceTest {
    @Mock
    private DeviceRepository deviceRepository;

    @Mock
    private AuthPipelineService authPipelineService;

    @InjectMocks
    private DeviceQueryService deviceQueryService;

    @Test
    void listOtherDevices_shouldReturnDevicesForAuthUserExcludingCurrentDevice() throws Exception {
        AuthData authData = TestModelFactory.authData();
        DeviceListRequestDto request = new DeviceListRequestDto(
            authData.deviceAuthData().publicId(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
        List<DeviceListItemDto> devices = List.of(new DeviceListItemDto(
            UUID.randomUUID(),
            DeviceType.BROWSER,
            "browser",
            Instant.now(),
            null,
            Instant.now()
        ));

        when(authPipelineService.verifyDeviceManagerRequest(any()))
            .thenReturn(authData);
        when(deviceRepository.findByUserIdExcludingDeviceId(anyLong(), anyLong()))
            .thenReturn(devices);

        var result = deviceQueryService.listOtherDevices(request);

        verify(authPipelineService).verifyDeviceManagerRequest(eq(DeviceListAuthRequest.from(request)));
        verify(deviceRepository).findByUserIdExcludingDeviceId(
            authData.userAuthData().id(),
            authData.deviceAuthData().id()
        );
        assertThat(result.devices()).isEqualTo(devices);
    }

}
