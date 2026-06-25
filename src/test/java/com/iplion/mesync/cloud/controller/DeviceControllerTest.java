package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
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
    private DeviceRevocationService deviceRevocationService;

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
    void revoke_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = deviceRevokeRequestDto();

        mockMvc.perform(post(TestUri.REVOKE_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void revoke_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRevocationService.revokeDevice(any())).thenThrow(new RuntimeException());

        mockMvc.perform(revokeMockRequest(deviceRevokeRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
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
    void revoke_shouldReturn200AndCallService() throws Exception {
        var requestDto = deviceRevokeRequestDto();
        mockMvc.perform(post(TestUri.REVOKE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.revoke")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk());

        verify(deviceRevocationService).revokeDevice(eq(requestDto));
    }

    // helpers

    MockHttpServletRequestBuilder revokeMockRequest(DeviceRevokeRequestDto requestDto) throws Exception {
        return post(TestUri.REVOKE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.revoke")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
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
