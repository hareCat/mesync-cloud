package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
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

@WebMvcTest(DeviceRegistrationController.class)
@Import(SecurityConfig.class)
public class DeviceRegistrationControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    private DeviceRegistrationService deviceRegistrationService;

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
    void storeInvite_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = storeInviteRequestDto();

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
    void storePublicKeys_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = storePublicKeysRequestDto();

        mockMvc.perform(post(TestUri.PUBLIC_KEY_URI)
                .with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.title").exists())
            .andExpect(jsonPath("$.instance").exists());
    }

    @Test
    void storeMasterKey_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        var requestDto = storeMasterKeyRequestDto();

        mockMvc.perform(post(TestUri.MASTER_KEY_URI)
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
    void storeInvite_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = storeInviteRequestDto();

        mockMvc.perform(post(TestUri.INVITE_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void storePublicKeys_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = storePublicKeysRequestDto();

        mockMvc.perform(post(TestUri.PUBLIC_KEY_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void storeMasterKey_shouldReturn401_whenNoJwt() throws Exception {
        var requestDto = storeMasterKeyRequestDto();

        mockMvc.perform(post(TestUri.MASTER_KEY_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void register_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.registerDevice(any())).thenThrow(new RuntimeException());

        mockMvc.perform(registerMockRequest(deviceRegisterRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void storeInvite_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.storeInviteToken(any())).thenThrow(new RuntimeException());

        mockMvc.perform(storeInviteMockRequest(storeInviteRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void storePublicKeys_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.storePublicKeys(any())).thenThrow(new RuntimeException());

        mockMvc.perform(storePublicKeysMockRequest(storePublicKeysRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void storeMasterKey_shouldReturnHttpError_whenServiceException() throws Exception {
        when(deviceRegistrationService.storeMasterKey(any())).thenThrow(new RuntimeException());

        mockMvc.perform(storeMasterKeyMockRequest(storeMasterKeyRequestDto()))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.detail", containsString("try again")));
    }

    @Test
    void register_shouldReturn400_whenRequestFieldBlank() throws Exception {
        String inviteToken = TestModelFactory.inviteToken();

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "",
                "a".repeat(44), Map.of(), inviteToken, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "testDevice",
                "",
                Map.of(), inviteToken, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "test device", "a".repeat(44), Map.of(),
                "",
                UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "test device", "a".repeat(44), Map.of(), inviteToken, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storeInvite_shouldReturn400_whenRequestFieldBlank() throws Exception {
        String inviteToken = TestModelFactory.inviteToken();

        mockMvc.perform(storeInviteMockRequest(new StoreInviteRequestDto(
                UUID.randomUUID(),
                "",
                1, DeviceType.MOBILE, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storeInviteMockRequest(new StoreInviteRequestDto(
                UUID.randomUUID(), inviteToken,
                1, DeviceType.MOBILE, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isCreated());

        mockMvc.perform(storeInviteMockRequest(new StoreInviteRequestDto(
                UUID.randomUUID(), inviteToken, 1, DeviceType.MOBILE, UUID.randomUUID(),
                ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storePublicKeys_shouldReturn400_whenRequestFieldBlank() throws Exception {
        String inviteToken = TestModelFactory.inviteToken();

        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                "",
                "a".repeat(44), "a".repeat(44), UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                inviteToken,
                "", "a".repeat(44), UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                inviteToken,
                "a".repeat(44), "", UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                inviteToken,
                "a".repeat(44), "a".repeat(44), UUID.randomUUID(), ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storeMasterKey_shouldReturn400_whenRequestFieldBlank() throws Exception {
        String inviteToken = TestModelFactory.inviteToken();

        mockMvc.perform(storeMasterKeyMockRequest(new StoreMasterKeyRequestDto(
                UUID.randomUUID(),
                "", "a".repeat(32), 1, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storeMasterKeyMockRequest(new StoreMasterKeyRequestDto(
                UUID.randomUUID(),
                inviteToken, "", 1, UUID.randomUUID(), "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storeMasterKeyMockRequest(new StoreMasterKeyRequestDto(
                UUID.randomUUID(),
                inviteToken, "a".repeat(32), 1, UUID.randomUUID(), ""
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void register_shouldReturn400_whenInviteTokenFormatInvalid() throws Exception {
        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "test device",
                "a".repeat(44),
                Map.of(),
                UUID.randomUUID().toString(),
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(registerMockRequest(new DeviceRegisterRequestDto(
                "test device",
                "a".repeat(44),
                Map.of(),
                "abc123",
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storeInvite_shouldReturn400_whenInviteTokenFormatInvalid() throws Exception {
        mockMvc.perform(storeInviteMockRequest(new StoreInviteRequestDto(
                UUID.randomUUID(),
                "ABC12",
                1,
                DeviceType.MOBILE,
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storeInviteMockRequest(new StoreInviteRequestDto(
                UUID.randomUUID(),
                "abc123",
                1,
                DeviceType.MOBILE,
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storePublicKeys_shouldReturn400_whenInviteTokenFormatInvalid() throws Exception {
        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                "ABC12",
                "a".repeat(44),
                "a".repeat(44),
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storePublicKeysMockRequest(new StorePublicKeysRequestDto(
                "abc123",
                "a".repeat(44),
                "a".repeat(44),
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());
    }

    @Test
    void storeMasterKey_shouldReturn400_whenInviteTokenFormatInvalid() throws Exception {
        mockMvc.perform(storeMasterKeyMockRequest(new StoreMasterKeyRequestDto(
                UUID.randomUUID(),
                "ABC12",
                "a".repeat(32),
                1,
                UUID.randomUUID(),
                "a".repeat(80)
            )))
            .andExpect(status().isBadRequest());

        mockMvc.perform(storeMasterKeyMockRequest(new StoreMasterKeyRequestDto(
                UUID.randomUUID(),
                "abc123",
                "a".repeat(32),
                1,
                UUID.randomUUID(),
                "a".repeat(80)
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

        verify(deviceRegistrationService).registerDevice(eq(requestDto));
    }

    @Test
    void storeInvite_shouldReturn201AndCallService() throws Exception {
        var requestDto = storeInviteRequestDto();
        mockMvc.perform(post(TestUri.INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).storeInviteToken(eq(requestDto));
    }

    @Test
    void storePublicKeys_shouldReturn201AndCallService() throws Exception {
        var requestDto = storePublicKeysRequestDto();
        mockMvc.perform(post(TestUri.PUBLIC_KEY_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).storePublicKeys(eq(requestDto));
    }

    @Test
    void storeMasterKey_shouldReturn201AndCallService() throws Exception {
        var requestDto = storeMasterKeyRequestDto();
        mockMvc.perform(post(TestUri.MASTER_KEY_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).storeMasterKey(eq(requestDto));
    }

    // --------------------------- helpers ---------------------------

    MockHttpServletRequestBuilder registerMockRequest(DeviceRegisterRequestDto requestDto) throws Exception {
        return post(TestUri.REGISTER_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder storeInviteMockRequest(StoreInviteRequestDto requestDto) throws Exception {
        return post(TestUri.INVITE_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.invite")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder storePublicKeysMockRequest(StorePublicKeysRequestDto requestDto) throws Exception {
        return post(TestUri.PUBLIC_KEY_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto));
    }

    MockHttpServletRequestBuilder storeMasterKeyMockRequest(StoreMasterKeyRequestDto requestDto) throws Exception {
        return post(TestUri.MASTER_KEY_URI).with(TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE)
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
            TestModelFactory.inviteToken(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    StoreInviteRequestDto storeInviteRequestDto() {
        return new StoreInviteRequestDto(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            1,
            DeviceType.BROWSER,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    StorePublicKeysRequestDto storePublicKeysRequestDto() {
        return new StorePublicKeysRequestDto(
            TestModelFactory.inviteToken(),
            "a".repeat(44),
            "a".repeat(44),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    StoreMasterKeyRequestDto storeMasterKeyRequestDto() {
        return new StoreMasterKeyRequestDto(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            "a".repeat(32),
            1,
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
