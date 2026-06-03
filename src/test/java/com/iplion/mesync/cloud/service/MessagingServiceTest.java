package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.AuthException;
import com.iplion.mesync.cloud.error.MessagingException;
import com.iplion.mesync.cloud.event.MessagePublishedEvent;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.MessageRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.SecurityService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MessagingServiceTest {
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserRepository userRepository;
    @Mock
    MessageRepository messageRepository;
    @Mock
    SecurityService securityService;
    @Mock
    ApplicationEventPublisher applicationEventPublisher;

    @InjectMocks
    MessagingService messagingService;

    @Test
    void publish_shouldPublishNewMessage() {
        DeviceAuthData deviceAuthData = deviceAuthData();
        Message message = message();
        MessagePublishRequestDto request = messagePublishRequestDto();

        when(securityService.verifyMessagingRequest(any())).thenReturn(deviceAuthData);
        when(userRepository.getReferenceById(any())).thenReturn(mock(User.class));
        when(deviceRepository.getReferenceById(any())).thenReturn(mock(Device.class));
        when(messageRepository.save(any())).thenReturn(message);

        var result = messagingService.publish(mock(Jwt.class), request);

        ArgumentCaptor<Message> savedMessageCaptor = ArgumentCaptor.forClass(Message.class);
        verify(messageRepository).save(savedMessageCaptor.capture());
        Message savedMessage = savedMessageCaptor.getValue();

        ArgumentCaptor<MessagePublishedEvent> eventCaptor = ArgumentCaptor.forClass(MessagePublishedEvent.class);
        verify(applicationEventPublisher).publishEvent(eventCaptor.capture());

        verify(userRepository).getReferenceById(deviceAuthData.userId());
        verify(deviceRepository).getReferenceById(deviceAuthData.deviceId());

        assertThat(savedMessage.getPublicId()).isEqualTo(request.messagePublicId());
        assertThat(savedMessage.getAddress()).isEqualTo(request.address());
        assertThat(savedMessage.getMessageType()).isEqualTo(request.messageType());
        assertThat(savedMessage.getDirection()).isEqualTo(request.direction());
        assertThat(savedMessage.getOccurredAt()).isEqualTo(request.occurredAt());
        assertThat(savedMessage.getKeyVersion()).isEqualTo(request.keyVersion());
        assertThat(savedMessage.getCiphertext()).isEqualTo(Base64.getDecoder().decode(request.base64Ciphertext()));

        assertThat(eventCaptor.getValue().userId()).isEqualTo(deviceAuthData.userId());
        assertThat(eventCaptor.getValue().excludeDeviceId()).isEqualTo(deviceAuthData.deviceId());

        assertThat(result.messagePublicId()).isEqualTo(message.getPublicId());
    }

    @Test
    void publish_shouldThrow_whenCiphertextInvalid() {
        MessagePublishRequestDto request = messagePublishRequestDto("invalid  base64 !");

        when(securityService.verifyMessagingRequest(any())).thenReturn(deviceAuthData());

        assertThatThrownBy(() -> messagingService.publish(mock(Jwt.class), request))
            .isInstanceOf(MessagingException.class)
            .hasCauseInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ciphertext");

        verifyNoInteractions(userRepository);
        verifyNoInteractions(deviceRepository);
        verifyNoInteractions(messageRepository);
        verifyNoInteractions(applicationEventPublisher);
    }

    @Test
    void publish_shouldThrow_whenSavingMessageError() {
        when(securityService.verifyMessagingRequest(any())).thenReturn(deviceAuthData());
        when(userRepository.getReferenceById(any())).thenReturn(mock(User.class));
        when(deviceRepository.getReferenceById(any())).thenReturn(mock(Device.class));
        when(messageRepository.save(any())).thenThrow(DataIntegrityViolationException.class);

        assertThatThrownBy(() -> messagingService.publish(mock(Jwt.class), messagePublishRequestDto()))
            .isInstanceOf(MessagingException.class)
            .hasCauseInstanceOf(DataIntegrityViolationException.class)
            .hasMessageContaining("saving");
    }

    @Test
    void sync_shouldGetMessagesAfterId() {
        DeviceAuthData deviceAuthData = deviceAuthData();
        int messagesRequestNum = 3;
        List<SyncMessageDto> messages = LongStream.rangeClosed(8L, 50L)
            .mapToObj(this::syncMessageDto)
            .toList();
        MessageSyncRequestDto request = messageSyncRequestDto(10L, messagesRequestNum);

        when(securityService.verifyMessagingRequest(any())).thenReturn(deviceAuthData);
        when(messageRepository.findNextAfterIdByUserExcludingDevice(any(), any(), any(), any())).thenReturn(messages);

        var result = messagingService.sync(mock(Jwt.class), request);

        ArgumentCaptor<Long> captorUserId = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<Long> captorDeviceId = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<Long> captorLastMessageId = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<Pageable> captorPageable = ArgumentCaptor.forClass(Pageable.class);
        verify(messageRepository).findNextAfterIdByUserExcludingDevice(
            captorUserId.capture(),
            captorDeviceId.capture(),
            captorLastMessageId.capture(),
            captorPageable.capture()
        );

        assertThat(captorUserId.getValue()).isEqualTo(deviceAuthData.userId());
        assertThat(captorDeviceId.getValue()).isEqualTo(deviceAuthData.deviceId());
        assertThat(captorLastMessageId.getValue()).isEqualTo(request.lastMessageId());

        Pageable pageable = captorPageable.getValue();
        assertThat(pageable.getPageNumber()).isEqualTo(0);
        assertThat(pageable.getPageSize()).isEqualTo(messagesRequestNum);
        assertThat(pageable.getOffset()).isEqualTo(0);

        assertThat(result.messages()).containsExactlyElementsOf(messages);
    }

    @Test
    void sync_shouldGetMessagesAfterIdWithMaxPerSyncLimit() {
        DeviceAuthData deviceAuthData = deviceAuthData();
        int messagesRequestNum = 100;
        final int MAX_MESSAGES_PER_SYNC_REQUEST = 20;
        List<SyncMessageDto> messages = LongStream.rangeClosed(8L, 50L)
            .mapToObj(this::syncMessageDto)
            .toList();
        MessageSyncRequestDto request = messageSyncRequestDto(10L, messagesRequestNum);

        when(securityService.verifyMessagingRequest(any())).thenReturn(deviceAuthData);
        when(messageRepository.findNextAfterIdByUserExcludingDevice(any(), any(), any(), any())).thenReturn(messages);

        var result = messagingService.sync(mock(Jwt.class), request);

        ArgumentCaptor<Pageable> captorPageable = ArgumentCaptor.forClass(Pageable.class);
        verify(messageRepository).findNextAfterIdByUserExcludingDevice(
            any(),
            any(),
            any(),
            captorPageable.capture()
        );

        assertThat(captorPageable.getValue().getPageSize()).isEqualTo(MAX_MESSAGES_PER_SYNC_REQUEST);
        assertThat(result.messages().size()).isEqualTo(messages.size());
    }

    @Test
    void sync_shouldThrow_whenAuthVerifyError() {
        MessageSyncRequestDto request = messageSyncRequestDto(0L, 10);

        when(securityService.verifyMessagingRequest(any()))
            .thenThrow(AuthException.wrongRequestData("bad", null));

        assertThatThrownBy(() -> messagingService.sync(mock(Jwt.class), request))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("bad");
    }

    // --------------------- helpers ---------------------

    private MessageSyncRequestDto messageSyncRequestDto(long lastMessageId, int limit) {
        return new MessageSyncRequestDto(
            UUID.randomUUID(),
            lastMessageId,
            limit,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    private MessagePublishRequestDto messagePublishRequestDto() {
        return messagePublishRequestDto("a".repeat(20));
    }

    private MessagePublishRequestDto messagePublishRequestDto(String base64Ciphertext) {
        return new MessagePublishRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "address",
            MessageType.SMS,
            MessageDirection.INCOMING,
            Instant.now(),
            2,
            base64Ciphertext,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    private DeviceAuthData deviceAuthData() {
        return new DeviceAuthData(
            1L,
            UUID.randomUUID(),
            1L,
            UUID.randomUUID(),
            DeviceType.MOBILE,
            mock(PublicKey.class),
            2
        );
    }

    private Message message() {
        Message message = new Message();
        message.setPublicId(UUID.randomUUID());
        message.setUser(mock(User.class));
        message.setDevice(mock(Device.class));
        message.setAddress("+995 123 456 789");
        message.setMessageType(MessageType.SMS);
        message.setDirection(MessageDirection.INCOMING);
        message.setOccurredAt(Instant.now());
        message.setKeyVersion(2);
        message.setCiphertext(new byte[44]);

        return message;
    }

    private SyncMessageDto syncMessageDto(Long id) {
        return new SyncMessageDto(
            id,
            UUID.randomUUID(),
            UUID.randomUUID(),
            "+995 123 456 789",
            MessageType.SMS,
            MessageDirection.INCOMING,
            Instant.now(),
            2,
            new byte[44]
        );
    }

}
