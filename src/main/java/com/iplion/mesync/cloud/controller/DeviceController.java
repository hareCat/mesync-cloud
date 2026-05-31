package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteResponseDto;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
public class DeviceController {
    private final DeviceRegistrationService deviceRegistrationService;
    private final DeviceRevocationService deviceRevocationService;

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    public DeviceRegisterResponseDto register(
        @AuthenticationPrincipal Jwt jwt,
        @Valid @RequestBody DeviceRegisterRequestDto request
    ) {
        return deviceRegistrationService.registerDevice(jwt, request);
    }

    @PostMapping("/invite")
    @PreAuthorize("hasAuthority('devices.invite')")
    @ResponseStatus(HttpStatus.CREATED)
    public SaveInviteResponseDto saveInvite(
        @AuthenticationPrincipal Jwt jwt,
        @Valid @RequestBody SaveInviteRequestDto request
    ) {
        return deviceRegistrationService.saveInviteToken(jwt, request);
    }

    @PostMapping("/revoke")
    @PreAuthorize("hasAuthority('devices.revoke')")
    public DeviceRevokeResponseDto revoke(
        @AuthenticationPrincipal Jwt jwt,
        @Valid @RequestBody DeviceRevokeRequestDto request
    ) {
        return deviceRevocationService.revokeDevice(jwt, request);
    }

}
