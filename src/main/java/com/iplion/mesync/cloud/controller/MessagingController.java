package com.iplion.mesync.cloud.controller;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessagePublishResponseDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncResponseDto;
import com.iplion.mesync.cloud.service.MessagingService;
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
public class MessagingController {
    private final MessagingService messagingService;

    @PostMapping("/publish")
    @PreAuthorize("hasAuthority('messages.publish')")
    @ResponseStatus(HttpStatus.CREATED)
    public MessagePublishResponseDto publish(
        @Valid @RequestBody MessagePublishRequestDto request
    ) {
        return messagingService.publish(request);
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAuthority('messages.read')")
    public MessageSyncResponseDto sync(
        @Valid @RequestBody MessageSyncRequestDto request
    ) {
        return messagingService.sync(request);
    }

}
