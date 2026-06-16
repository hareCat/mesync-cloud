package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessagePublishResponseDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncResponseDto;
import com.iplion.mesync.cloud.service.MessagingService;
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
@RequestMapping("/api/v1/messages")
@RequiredArgsConstructor
@Tag(name = "Messages", description = "Encrypted message publishing and synchronization")
@SecurityRequirement(name = "bearerAuth")
public class MessagingController {
    private final MessagingService messagingService;

    @PostMapping("/publish")
    @PreAuthorize("hasAuthority('messages.publish')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Publish encrypted message",
        description = "Stores one encrypted message record from a registered device" +
            " for later synchronization by the user's other devices. Requires authority messages.publish.",
        responses = {
            @ApiResponse(responseCode = "201", description = "Message stored"),
            @ApiResponse(responseCode = "400", description = "Invalid request body"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority")
        }
    )
    public MessagePublishResponseDto publish(
        @Valid @RequestBody MessagePublishRequestDto request
    ) {
        return messagingService.publish(request);
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAuthority('messages.read')")
    @Operation(
        summary = "Sync encrypted messages",
        description = "Returns encrypted message records for the authenticated user," +
            " excluding records published by the requesting device. Requires authority messages.read.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Messages returned"),
            @ApiResponse(responseCode = "400", description = "Invalid request body"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Missing required authority")
        }
    )
    public MessageSyncResponseDto sync(
        @Valid @RequestBody MessageSyncRequestDto request
    ) {
        return messagingService.sync(request);
    }

}
