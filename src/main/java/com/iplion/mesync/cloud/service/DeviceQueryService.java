package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.device.DeviceListRequestDto;
import com.iplion.mesync.cloud.controller.dto.device.DeviceListResponseDto;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.request.DeviceListAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeviceQueryService {
    private final DeviceRepository deviceRepository;
    private final AuthPipelineService authPipelineService;

    public DeviceListResponseDto listOtherDevices(DeviceListRequestDto request) {
        AuthData authData = authPipelineService.verifyDeviceManagerRequest(
            DeviceListAuthRequest.from(request)
        );

        return new DeviceListResponseDto(
            deviceRepository.findByUserIdExcludingDeviceId(
                authData.userAuthData().id(),
                authData.deviceAuthData().id()
            )
        );
    }

}
