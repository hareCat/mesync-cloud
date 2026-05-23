package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessagePublishResponseDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncResponseDto;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.error.MessagingException;
import com.iplion.mesync.cloud.event.MessagePublishedEvent;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.MessageRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.SecurityService;
import com.iplion.mesync.cloud.security.auth.DeviceAuthResult;
import com.iplion.mesync.cloud.security.auth.MessagePublishAuthRequest;
import com.iplion.mesync.cloud.security.auth.MessageSyncAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MessagingService {

    private final SecurityService securityService;
    private final MessageRepository messageRepository;
    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final ApplicationEventPublisher applicationEventPublisher;

    private static final int MAX_MESSAGES_PER_SYNC_REQUEST = 20;

    @Transactional
    public MessagePublishResponseDto publish(Jwt jwt, MessagePublishRequestDto request) {
        DeviceAuthResult authResult = securityService.verifyMessagingRequest(MessagePublishAuthRequest.from(jwt, request));

        Message message;
        try {
            messageRepository.save(message = buildMessage(request, authResult));
        } catch (IllegalArgumentException e) {
            throw MessagingException.cryptographyFailed(
                String.format("Invalid base64 ciphertext. messageId: %s, userId: %d, deviceId: %d",
                    request.messageId(),
                    authResult.deviceAuthData().userId(),
                    authResult.deviceAuthData().id()
                ), e
            );
        } catch (DataIntegrityViolationException e) {
            throw MessagingException.messageSaving(
                String.format("Message saving error. messageId: %s, userId: %d, deviceId: %d",
                    request.messageId(),
                    authResult.deviceAuthData().userId(),
                    authResult.deviceAuthData().id()
                ), e
            );
        }

        applicationEventPublisher.publishEvent(
            new MessagePublishedEvent(
                authResult.deviceAuthData().userId(),
                authResult.deviceAuthData().id()
            )
        );

        return new MessagePublishResponseDto(
            message.getPublicId()
        );
    }

    public MessageSyncResponseDto sync(Jwt jwt, MessageSyncRequestDto request) {
        DeviceAuthResult authResult = securityService.verifyMessagingRequest(MessageSyncAuthRequest.from(jwt, request));

        DeviceAuthData deviceAuthData = authResult.deviceAuthData();
        List<SyncMessageDto> messages = messageRepository.findNextAfterId(
            deviceAuthData.userId(),
            deviceAuthData.id(),
            request.lastMessageId(),
            PageRequest.of(0, Math.min(MAX_MESSAGES_PER_SYNC_REQUEST, request.limit()))
        );

        return new MessageSyncResponseDto(messages);
    }

    private Message buildMessage(MessagePublishRequestDto request, DeviceAuthResult authResult) {
        byte[] ciphertext = Base64.getDecoder().decode(request.base64Ciphertext());

        Message message = new Message();
        message.setPublicId(request.messageId());
        message.setUser(userRepository.getReferenceById(authResult.deviceAuthData().userId()));
        message.setDevice(deviceRepository.getReferenceById(authResult.deviceAuthData().id()));
        message.setAddress(request.address());
        message.setMessageType(request.messageType());
        message.setDirection(request.direction());
        message.setOccurredAt(request.occurredAt());
        message.setKeyVersion(request.keyVersion());
        message.setCiphertext(ciphertext);

        return message;
    }
}
