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
@RequestMapping("/api/v1/register")
@RequiredArgsConstructor
@Tag(name = "Devices", description = "Device registration flow")
@SecurityRequirement(name = "bearerAuth")
public class DeviceRegistrationController {
    private final DeviceRegistrationService deviceRegistrationService;

    @PostMapping
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Register device",
        description = "Registers the first mobile device or completes an additional-device invite. " +
            "For additional devices, the request consumes a ready invite after validating the invited signing key, " +
            "returns the encrypted master key, and deletes the invite after the device is saved. " +
            "Device type is derived from the JWT azp claim. Requires authority messages.read.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Device registered"),
            @ApiResponse(responseCode = "400", description = "Invalid request body or invite state"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority, replay/rate limit, or invite lock")
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
        description = "Stores a one-time invite token and the target device type for connecting an additional device. " +
            "The invited device public keys and encrypted master key are stored by later registration steps. " +
            "Requires authority devices.invite.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Invite token stored"),
            @ApiResponse(responseCode = "400", description = "Invalid request body"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority, replay/rate limit, or invite cooldown"),
            @ApiResponse(responseCode = "409", description = "Master key version mismatch")
        }
    )
    public StoreInviteResponseDto storeInvite(
        @Valid @RequestBody StoreInviteRequestDto request
    ) {
        return deviceRegistrationService.storeInviteToken(request);
    }

    @PostMapping("/public-key")
    @PreAuthorize("hasAuthority('messages.read')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Store invited device public keys",
        description = "Stores the invited device encryption public key and signing public key in the Redis invite. " +
            "The request is signed by the invited device signing key as proof of possession. " +
            "Requires authority messages.read.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Public keys stored in invite"),
            @ApiResponse(responseCode = "400", description = "Invalid request body or invite token"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority, replay/rate limit, or cooldown")
        }
    )
    public StorePublicKeysResponseDto storePublicKeys(
        @Valid @RequestBody StorePublicKeysRequestDto request
    ) {
        return deviceRegistrationService.storePublicKeys(request);
    }

    @PostMapping("/master-key")
    @PreAuthorize("hasAuthority('devices.invite')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Store encrypted master key for invite",
        description = "Stores the master key encrypted by the invited device encryption public key. " +
            "The invite must already contain the invited device public keys. Requires authority devices.invite.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Encrypted master key stored in invite"),
            @ApiResponse(responseCode = "400", description = "Invalid request body or public keys are not ready"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority, replay/rate limit, or cooldown")
        }
    )
    public StoreMasterKeyResponseDto storeMasterKey(
        @Valid @RequestBody StoreMasterKeyRequestDto request
    ) {
        return deviceRegistrationService.storeMasterKey(request);
    }

}
