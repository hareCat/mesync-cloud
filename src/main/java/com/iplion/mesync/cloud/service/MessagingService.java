package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessagePublishResponseDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncResponseDto;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.error.api.MessagingException;
import com.iplion.mesync.cloud.event.MessagePublishedEvent;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.MessageRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.AuthService;
import com.iplion.mesync.cloud.security.SecurityContextUtils;
import com.iplion.mesync.cloud.security.auth.MessagePublishAuthRequest;
import com.iplion.mesync.cloud.security.auth.MessageSyncAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MessagingService {

    private final AuthService authService;
    private final MessageRepository messageRepository;
    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final ApplicationEventPublisher applicationEventPublisher;

    private static final int MAX_MESSAGES_PER_SYNC_REQUEST = 20;

    @Transactional
    public MessagePublishResponseDto publish(MessagePublishRequestDto request) {
        authService.verifyMessagingRequest(MessagePublishAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        Message message;
        try {
            message = messageRepository.save(buildMessage(request, authData));
        } catch (IllegalArgumentException e) {
            throw MessagingException.invalidCryptographyData(
                String.format("Invalid base64 ciphertext. messagePublicId: %s",
                    request.messagePublicId()
                ), e
            );
        } catch (DataIntegrityViolationException e) {
            throw MessagingException.messageSaving(
                String.format("Message saving error. messagePublicId: %s",
                    request.messagePublicId()
                ), e
            );
        }

        applicationEventPublisher.publishEvent(
            new MessagePublishedEvent(
                authData.userAuthData().id(),
                authData.deviceAuthData().id()
            )
        );

        return new MessagePublishResponseDto(message.getPublicId());
    }

    public MessageSyncResponseDto sync(MessageSyncRequestDto request) {
        authService.verifyMessagingRequest(MessageSyncAuthRequest.from(request));
        AuthData authData = SecurityContextUtils.getAuthData();

        List<SyncMessageDto> syncMessageDtos = messageRepository.findNextAfterIdByUserExcludingDevice(
            authData.userAuthData().id(),
            authData.deviceAuthData().id(),
            request.lastMessageId(),
            PageRequest.of(0, Math.min(MAX_MESSAGES_PER_SYNC_REQUEST, request.limit()))
        );

        return new MessageSyncResponseDto(syncMessageDtos);
    }

    private Message buildMessage(MessagePublishRequestDto request, AuthData authData) {
        byte[] ciphertext = Base64.getDecoder().decode(request.base64Ciphertext());

        Message message = new Message();
        message.setPublicId(request.messagePublicId());
        message.setUser(userRepository.getReferenceById(authData.userAuthData().id()));
        message.setDevice(deviceRepository.getReferenceById(authData.deviceAuthData().id()));
        message.setAddress(request.address());
        message.setMessageType(request.messageType());
        message.setDirection(request.direction());
        message.setOccurredAt(request.occurredAt());
        message.setKeyVersion(request.keyVersion());
        message.setCiphertext(ciphertext);

        return message;
    }
}
