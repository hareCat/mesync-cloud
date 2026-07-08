package com.iplion.mesync.cloud.controller.dto.message;

import java.util.List;

// TODO add lastMessageId
public record MessageSyncResponseDto(
    List<SyncMessageDto> messages
) {
}
