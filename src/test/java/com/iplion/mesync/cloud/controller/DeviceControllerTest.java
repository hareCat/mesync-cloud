package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
import com.iplion.mesync.cloud.service.InvitationService;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestUri;
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

    @MockitoBean
    DeviceRevocationService deviceRevocationService;

    @Test
    void register_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = deviceRegisterRequestDto();

        mockMvc.perform(post(TestUri.REGISTER_URI)
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
    void saveInvite_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = saveInviteRequestDto();

        mockMvc.perform(post(TestUri.INVITE_URI)
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
    void revoke_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = deviceRevokeRequestDto();

        mockMvc.perform(post(TestUri.REVOKE_URI)
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
    void register_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = deviceRegisterRequestDto();

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void saveInvite_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = saveInviteRequestDto();

        mockMvc.perform(post(TestUri.INVITE_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void revoke_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = deviceRevokeRequestDto();

        mockMvc.perform(post(TestUri.REVOKE_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void register_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.registerDevice(any(), any())).thenThrow(new RuntimeException());

        mockMvc.perform(registerMockRequest(deviceRegisterRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void saveInvite_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.saveInviteToken(any(), any())).thenThrow(new RuntimeException());

        mockMvc.perform(saveInviteMockRequest(saveInviteRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void revoke_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRevocationService.revokeDevice(any(), any())).thenThrow(new RuntimeException());

        mockMvc.perform(revokeMockRequest(deviceRevokeRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void register_shouldReturn400_whenRequestFieldBlank() throws Exception {
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
    void saveInvite_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(saveInviteMockRequest(new SaveInviteRequestDto(
                UUID.randomUUID(), UUID.randomUUID(),
                "",
                1, DeviceType.MOBILE, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(saveInviteMockRequest(new SaveInviteRequestDto(
                UUID.randomUUID(), UUID.randomUUID(), "a".repeat(44), 1, DeviceType.MOBILE, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void revoke_shouldReturn400_whenRequestFieldBlank() throws Exception {
        mockMvc.perform(revokeMockRequest(new DeviceRevokeRequestDto(
                UUID.randomUUID(), UUID.randomUUID(), true, 1, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void register_shouldReturn201AndCallService() throws Exception {
        var requestDto = deviceRegisterRequestDto();
        mockMvc.perform(post(TestUri.REGISTER_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).registerDevice(any(Jwt.class), eq(requestDto));
    }

    @Test
    void saveInvite_shouldReturn201AndCallService() throws Exception {
        var requestDto = saveInviteRequestDto();
        mockMvc.perform(post(TestUri.INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).saveInviteToken(any(Jwt.class), eq(requestDto));
    }

    @Test
    void revoke_shouldReturn200AndCallService() throws Exception {
        var requestDto = deviceRevokeRequestDto();
        mockMvc.perform(post(TestUri.REVOKE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.revoke")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk());

        verify(deviceRevocationService).revokeDevice(any(Jwt.class), eq(requestDto));
    }

    // helpers

    MockHttpServletRequestBuilder registerMockRequest(DeviceRegisterRequestDto requestDto) throws Exception {
        return post(TestUri.REGISTER_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder saveInviteMockRequest(SaveInviteRequestDto requestDto) throws Exception {
        return post(TestUri.INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.invite")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder revokeMockRequest(DeviceRevokeRequestDto requestDto) throws Exception {
        return post(TestUri.REVOKE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.revoke")))
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
            1,
            DeviceType.BROWSER,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    public static DeviceRevokeRequestDto deviceRevokeRequestDto() {
        return new DeviceRevokeRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            true,
            3,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
