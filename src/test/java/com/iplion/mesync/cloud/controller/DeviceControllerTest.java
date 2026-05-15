package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.service.InvitationService;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DeviceController.class)
@Import(SecurityConfig.class)
public class DeviceControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    private DeviceRegistrationService deviceRegistrationService;

    @MockitoBean
    private InvitationService invitationService;

    private static final String REGISTER_URI = "/api/v1/devices/register";
    private static final String INVITE_URI = "/api/v1/devices/invite";

    @Test
    void saveInvite_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = saveInviteRequestDto();

        mockMvc.perform(post(INVITE_URI)
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
    void registerDevice_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = deviceRegisterRequestDto();

        mockMvc.perform(post(REGISTER_URI)
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
    void registerDevice_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = deviceRegisterRequestDto();

        mockMvc.perform(post(REGISTER_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void saveInviteToken_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = saveInviteRequestDto();

        mockMvc.perform(post(INVITE_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void registerDevice_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.registerDevice(any(), any())).thenThrow(new RuntimeException());

        mockMvc.perform(registerMockRequest(deviceRegisterRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void saveInviteTiken_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.saveInviteToken(any(), any())).thenThrow(new RuntimeException());

        mockMvc.perform(saveInviteMockRequest(saveInviteRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void registerDevice_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "",
                "a".repeat(44), Map.of(), UUID.randomUUID(), UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "testDevice",
                "",
                Map.of(), UUID.randomUUID(), UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "test device", "a".repeat(44), Map.of(), UUID.randomUUID(), UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void saveInviteToken_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(saveInviteMockRequest(new SaveInviteRequestDto(
                UUID.randomUUID(), UUID.randomUUID(),
                "",
                DeviceType.MOBILE, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(saveInviteMockRequest(new SaveInviteRequestDto(
                UUID.randomUUID(), UUID.randomUUID(), "a".repeat(44), DeviceType.MOBILE, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void registerDevice_shouldReturn201AndCallService() throws Exception {
        var requestDto = deviceRegisterRequestDto();
        mockMvc.perform(post(REGISTER_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).registerDevice(any(Jwt.class), eq(requestDto));
    }

    @Test
    void saveInviteToken_shouldReturn201AndCallService() throws Exception {
        var requestDto = saveInviteRequestDto();
        mockMvc.perform(post(INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).saveInviteToken(any(Jwt.class), eq(requestDto));
    }

    // helpers

    MockHttpServletRequestBuilder registerMockRequest(DeviceRegisterRequestDto requestDto) throws Exception {
        return post(REGISTER_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder saveInviteMockRequest(SaveInviteRequestDto requestDto) throws Exception {
        return post(INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.invite")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    DeviceRegisterRequestDto deviceRegisterRequestDto() {
        return new DeviceRegisterRequestDto(
            "test device",
            "a".repeat(44),
            Map.of("platform", "android"),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    SaveInviteRequestDto saveInviteRequestDto() {
        return new SaveInviteRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(32),
            DeviceType.BROWSER,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
