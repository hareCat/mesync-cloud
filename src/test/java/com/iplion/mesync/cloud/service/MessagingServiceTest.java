package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.error.api.MessagingException;
import com.iplion.mesync.cloud.event.MessagePublishedEvent;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.MessageRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class MessagingServiceTest extends BaseUnitTest {
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserRepository userRepository;
    @Mock
    MessageRepository messageRepository;
    @Mock
    AuthPipelineService authPipelineService;
    @Mock
    ApplicationEventPublisher applicationEventPublisher;

    @InjectMocks
    MessagingService messagingService;

    @Test
    void publish_shouldPublishNewMessage() throws Exception {
        AuthData authData = TestModelFactory.authData();

        User user = TestModelFactory.user();
        Message message = TestModelFactory.message(TestModelFactory.user(), TestModelFactory.device(user));
        MessagePublishRequestDto request = messagePublishRequestDto();

        when(authPipelineService.verifyMessagingRequest(any())).thenReturn(authData);
        when(userRepository.getReferenceById(any())).thenReturn(mock(User.class));
        when(deviceRepository.getReferenceById(any())).thenReturn(mock(Device.class));
        when(messageRepository.save(any())).thenReturn(message);

        var result = messagingService.publish(request);

        ArgumentCaptor<Message> savedMessageCaptor = ArgumentCaptor.forClass(Message.class);
        verify(messageRepository).save(savedMessageCaptor.capture());
        Message savedMessage = savedMessageCaptor.getValue();

        ArgumentCaptor<MessagePublishedEvent> eventCaptor = ArgumentCaptor.forClass(MessagePublishedEvent.class);
        verify(applicationEventPublisher).publishEvent(eventCaptor.capture());

        verify(userRepository).getReferenceById(authData.userAuthData().id());
        verify(deviceRepository).getReferenceById(authData.deviceAuthData().id());

        assertThat(savedMessage.getPublicId()).isEqualTo(request.messagePublicId());
        assertThat(savedMessage.getAddress()).isEqualTo(request.address());
        assertThat(savedMessage.getMessageType()).isEqualTo(request.messageType());
        assertThat(savedMessage.getDirection()).isEqualTo(request.direction());
        assertThat(savedMessage.getOccurredAt()).isEqualTo(request.occurredAt());
        assertThat(savedMessage.getKeyVersion()).isEqualTo(request.keyVersion());
        assertThat(savedMessage.getCiphertext()).isEqualTo(Base64.getDecoder().decode(request.base64Ciphertext()));

        assertThat(eventCaptor.getValue().userId()).isEqualTo(authData.userAuthData().id());
        assertThat(eventCaptor.getValue().excludeDeviceId()).isEqualTo(authData.deviceAuthData().id());

        assertThat(result.messagePublicId()).isEqualTo(message.getPublicId());
    }

    @Test
    void publish_shouldThrow_whenCiphertextInvalid() throws Exception {
        MessagePublishRequestDto request = messagePublishRequestDto("invalid  base64 !");
        AuthData authData = TestModelFactory.authData();

        when(authPipelineService.verifyMessagingRequest(any())).thenReturn(authData);

        assertThatThrownBy(() -> messagingService.publish(request))
            .isInstanceOfSatisfying(MessagingException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e).hasCauseInstanceOf(IllegalArgumentException.class);
                assertThat(e.getMessage()).contains("ciphertext");
            });

        verifyNoInteractions(userRepository);
        verifyNoInteractions(deviceRepository);
        verifyNoInteractions(messageRepository);
        verifyNoInteractions(applicationEventPublisher);
    }

    @Test
    void publish_shouldThrow_whenSavingMessageError() throws Exception {
        AuthData authData = TestModelFactory.authData();

        when(authPipelineService.verifyMessagingRequest(any())).thenReturn(authData);
        when(userRepository.getReferenceById(any())).thenReturn(mock(User.class));
        when(deviceRepository.getReferenceById(any())).thenReturn(mock(Device.class));
        when(messageRepository.save(any())).thenThrow(DataIntegrityViolationException.class);

        assertThatThrownBy(() -> messagingService.publish(messagePublishRequestDto()))
            .isInstanceOfSatisfying(MessagingException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.CONFLICT);
                assertThat(e).hasCauseInstanceOf(DataIntegrityViolationException.class);
                assertThat(e.getMessage()).contains("saving");
            });
    }

    @Test
    void sync_shouldGetMessagesAfterId() throws Exception {
        AuthData authData = TestModelFactory.authData();

        int messagesRequestNum = 3;
        List<SyncMessageDto> messages = LongStream.rangeClosed(8L, 50L)
            .mapToObj(this::syncMessageDto)
            .toList();
        MessageSyncRequestDto request = messageSyncRequestDto(10L, messagesRequestNum);

        when(authPipelineService.verifyMessagingRequest(any())).thenReturn(authData);
        when(messageRepository.findNextAfterIdByUserExcludingDevice(any(), any(), any(), any())).thenReturn(messages);

        var result = messagingService.sync(request);

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

        assertThat(captorUserId.getValue()).isEqualTo(authData.userAuthData().id());
        assertThat(captorDeviceId.getValue()).isEqualTo(authData.deviceAuthData().id());
        assertThat(captorLastMessageId.getValue()).isEqualTo(request.lastMessageId());

        Pageable pageable = captorPageable.getValue();
        assertThat(pageable.getPageNumber()).isEqualTo(0);
        assertThat(pageable.getPageSize()).isEqualTo(messagesRequestNum);
        assertThat(pageable.getOffset()).isEqualTo(0);

        assertThat(result.messages()).containsExactlyElementsOf(messages);
    }

    @Test
    void sync_shouldGetMessagesAfterIdWithMaxPerSyncLimit() throws Exception {
        AuthData authData = TestModelFactory.authData();

        int messagesRequestNum = 100;
        final int MAX_MESSAGES_PER_SYNC_REQUEST = 20;
        List<SyncMessageDto> messages = LongStream.rangeClosed(8L, 50L)
            .mapToObj(this::syncMessageDto)
            .toList();
        MessageSyncRequestDto request = messageSyncRequestDto(10L, messagesRequestNum);

        when(authPipelineService.verifyMessagingRequest(any())).thenReturn(authData);
        when(messageRepository.findNextAfterIdByUserExcludingDevice(any(), any(), any(), any())).thenReturn(messages);

        var result = messagingService.sync(request);

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

        doThrow(AuthException.wrongRequestData("bad", null))
            .when(authPipelineService).verifyMessagingRequest(any());

        assertThatThrownBy(() -> messagingService.sync(request))
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
