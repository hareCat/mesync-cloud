package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
public class DeviceController {
    private final DeviceRevocationService deviceRevocationService;

    @PostMapping("/revoke")
    @PreAuthorize("hasAuthority('devices.revoke')")
    public DeviceRevokeResponseDto revoke(
        @Valid @RequestBody DeviceRevokeRequestDto request
    ) {
        return deviceRevocationService.revokeDevice(request);
    }

}
