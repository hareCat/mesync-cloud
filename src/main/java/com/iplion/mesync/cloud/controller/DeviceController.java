package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.DeviceInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
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
    public DeviceInviteResponseDto saveInvite(
        @AuthenticationPrincipal Jwt jwt,
        @Valid @RequestBody DeviceInviteRequestDto request
    ) {
        return deviceRegistrationService.saveInviteToken(jwt, request);
    }
}
