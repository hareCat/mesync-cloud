package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.dto.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.service.MessagingService;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestUri;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(MessagingController.class)
@Import(SecurityConfig.class)
public class MessagingControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    private MessagingService messagingService;

    @Test
    void publish_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = messagePublishRequestDto();

        mockMvc.perform(post(TestUri.PUBLISH_URI)
                .with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.title").exists())
            .andExpect(jsonPath("$.instance").exists());
    }

    @Test
    void sync_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = messageSyncRequestDto();

        mockMvc.perform(post(TestUri.SYNC_URI)
                .with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.remove")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.title").exists())
            .andExpect(jsonPath("$.instance").exists());
    }

    @Test
    void publish_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = messagePublishRequestDto();

        mockMvc.perform(post(TestUri.PUBLISH_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void sync_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = messageSyncRequestDto();

        mockMvc.perform(post(TestUri.SYNC_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void publish_shouldReturnHttpError_whenServiceException() throws Exception {
        when(messagingService.publish(any())).thenThrow(new RuntimeException());

        mockMvc.perform(publishMockRequest(messagePublishRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void sync_shouldReturnHttpError_whenServiceException() throws Exception {
        when(messagingService.sync(any())).thenThrow(new RuntimeException());

        mockMvc.perform(syncMockRequest(messageSyncRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void publish_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(publishMockRequest(new MessagePublishRequestDto(
                UUID.randomUUID(), UUID.randomUUID(),
                "",
                MessageType.SMS, MessageDirection.INCOMING, Instant.now(), 1,
                "b".repeat(16), UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(publishMockRequest(new MessagePublishRequestDto(
                UUID.randomUUID(), UUID.randomUUID(), "address",
                MessageType.SMS, MessageDirection.INCOMING, Instant.now(), 1,
                "",
                UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(publishMockRequest(new MessagePublishRequestDto(
                UUID.randomUUID(), UUID.randomUUID(),
                "address",
                MessageType.SMS, MessageDirection.INCOMING, Instant.now(), 1,
                "b".repeat(16), UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void sync_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(syncMockRequest(new MessageSyncRequestDto(
                UUID.randomUUID(), 0L, 100, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void publish_shouldReturn201AndCallService() throws Exception {
        var requestDto = messagePublishRequestDto();
        mockMvc.perform(post(TestUri.PUBLISH_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.publish")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(messagingService).publish(eq(requestDto));
    }

    @Test
    void sync_shouldReturn201AndCallService() throws Exception {
        var requestDto = messageSyncRequestDto();
        mockMvc.perform(post(TestUri.SYNC_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk());

        verify(messagingService).sync(eq(requestDto));
    }

    // --------------------------- helpers ---------------------------

    MockHttpServletRequestBuilder publishMockRequest(MessagePublishRequestDto requestDto) throws Exception {
        return post(TestUri.PUBLISH_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.publish")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder syncMockRequest(MessageSyncRequestDto requestDto) throws Exception {
        return post(TestUri.SYNC_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MessagePublishRequestDto messagePublishRequestDto() {
        return new MessagePublishRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "address",
            MessageType.SMS,
            MessageDirection.INCOMING,
            Instant.now(),
            1,
            "b".repeat(16),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    MessageSyncRequestDto messageSyncRequestDto() {
        return new MessageSyncRequestDto(
            UUID.randomUUID(),
            0L,
            100,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
