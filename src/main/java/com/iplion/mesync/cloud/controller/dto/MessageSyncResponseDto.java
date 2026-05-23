package com.iplion.mesync.cloud.controller.dto;

import com.iplion.mesync.cloud.model.SyncMessageDto;

import java.util.List;

// TODO add lastMessageId
public record MessageSyncResponseDto(
    List<SyncMessageDto> messages
) {
}
