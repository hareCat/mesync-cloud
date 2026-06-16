package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeResponseDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteResponseDto;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
@Tag(name = "Devices", description = "Device registration, invites, and revocation")
@SecurityRequirement(name = "bearerAuth")
public class DeviceController {
    private final DeviceRegistrationService deviceRegistrationService;
    private final DeviceRevocationService deviceRevocationService;

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Register device",
        description = "Registers a device for the authenticated user. " +
            "Device type is derived from the JWT azp claim. Requires authority messages.read.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Device registered"),
            @ApiResponse(responseCode = "400", description = "Invalid request body"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority")
        }
    )
    public DeviceRegisterResponseDto register(
        @Valid @RequestBody DeviceRegisterRequestDto request
    ) {
        return deviceRegistrationService.registerDevice(request);
    }

    @PostMapping("/invite")
    @PreAuthorize("hasAuthority('devices.invite')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Create device invite",
        description = "Stores a one-time invite token and encrypted master key for connecting an additional device. " +
            "Requires authority devices.invite.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Invite stored"),
            @ApiResponse(responseCode = "400", description = "Invalid request body"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority")
        }
    )
    public SaveInviteResponseDto saveInvite(
        @Valid @RequestBody SaveInviteRequestDto request
    ) {
        return deviceRegistrationService.saveInviteToken(request);
    }

    @PostMapping("/revoke")
    @PreAuthorize("hasAuthority('devices.revoke')")
    @Operation(
        summary = "Revoke device",
        description = "Revokes a trusted device owned by the authenticated user " +
            "and optionally advances the user's master-key version. Requires authority devices.revoke.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Device revoked"),
            @ApiResponse(responseCode = "400", description = "Invalid request body or key version"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority"),
            @ApiResponse(responseCode = "404", description = "Target device not found")
        }
    )
    public DeviceRevokeResponseDto revoke(
        @Valid @RequestBody DeviceRevokeRequestDto request
    ) {
        return deviceRevocationService.revokeDevice(request);
    }

}
