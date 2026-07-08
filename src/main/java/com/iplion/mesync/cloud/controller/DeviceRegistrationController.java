package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteResponseDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyResponseDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysResponseDto;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/register")
@RequiredArgsConstructor
public class DeviceRegistrationController {
    private final DeviceRegistrationService deviceRegistrationService;

    @PostMapping
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    public DeviceRegisterResponseDto register(
        @Valid @RequestBody DeviceRegisterRequestDto request
    ) {
        return deviceRegistrationService.registerDevice(request);
    }

    @PostMapping("/invite")
    @PreAuthorize("hasAuthority('devices.invite')")
    @ResponseStatus(HttpStatus.CREATED)
    public StoreInviteResponseDto storeInvite(
        @Valid @RequestBody StoreInviteRequestDto request
    ) {
        return deviceRegistrationService.storeInviteToken(request);
    }

    @PostMapping("/public-key")
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    public StorePublicKeysResponseDto storePublicKeys(
        @Valid @RequestBody StorePublicKeysRequestDto request
    ) {
        return deviceRegistrationService.storePublicKeys(request);
    }

    @PostMapping("/master-key")
    @PreAuthorize("hasAuthority('devices.invite')")
    @ResponseStatus(HttpStatus.CREATED)
    public StoreMasterKeyResponseDto storeMasterKey(
        @Valid @RequestBody StoreMasterKeyRequestDto request
    ) {
        return deviceRegistrationService.storeMasterKey(request);
    }

}
