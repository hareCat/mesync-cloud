package com.iplion.mesync.cloud;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.SecurityConfig;
import com.iplion.mesync.cloud.controller.DeviceController;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.service.DeviceRegistrationService;
import com.iplion.mesync.cloud.service.DeviceRevocationService;
import com.iplion.mesync.cloud.testUtils.TestUri;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DeviceController.class)
@Import(SecurityConfig.class)
@Testcontainers
@ActiveProfiles("test")
public class KeycloakIT {
    @Container
    static KeycloakContainer keycloak =
        new KeycloakContainer("quay.io/keycloak/keycloak:26.5.2")
            .withRealmImportFile("keycloak/mesync-test-realm.json");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add(
            "spring.security.oauth2.resourceserver.jwt.issuer-uri",
            () -> keycloak.getAuthServerUrl() + "/realms/mesync-test"
        );
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    DeviceRegistrationService deviceRegistrationService;

    @MockitoBean
    DeviceRevocationService deviceRevocationService;

    @Test
    void keycloak_shouldRejectUnknownClient() {
        var e = Assertions.assertThrows(
            HttpClientErrorException.class,
            () -> getAccessToken("abracadabra")
        );

        Assertions.assertTrue(e.getResponseBodyAsString().contains("invalid_client"));
    }

    @Test
    void keycloak_shouldHaveRealmRolesIntoToken() {
        String token = getAccessToken(DeviceType.MOBILE);

        String payload = token.split("\\.")[1];

        String json = new String(Base64.getUrlDecoder().decode(payload));

        Assertions.assertTrue(
            json.contains("realm_access")
                && json.contains("messages.read")
                && json.contains("messages.write")
                && json.contains("messages.publish")
        );
    }

    @Test
    void keycloak_shouldRejectWrongPassword() {
        var e = Assertions.assertThrows(HttpClientErrorException.class,
            () -> getAccessToken(
                DeviceType.MOBILE.getClientId(),
                "wrong-password"
            )
        );

        Assertions.assertTrue(e.getResponseBodyAsString().contains("invalid_grant"));
    }

    @Test
    void registerDevice_shouldReturn201_whenTokenAndRolesValid() throws Exception {
        registerDevice(getAccessToken(DeviceType.MOBILE), deviceRegisterRequestDto())
            .andExpect(status().isCreated());

        verify(deviceRegistrationService).registerDevice(
            any(Jwt.class),
            any(DeviceRegisterRequestDto.class)
        );
    }

    @Test
    void registerDevice_shouldReturn401_whenTokenInvalid() throws Exception {
        registerDevice("InvalidToken", deviceRegisterRequestDto())
            .andExpect(status().isUnauthorized());

        verifyNoInteractions(deviceRegistrationService);
    }

    @Test
    void registerDevice_shouldReturn401_whenTokenMissing() throws Exception {
        mockMvc.perform(post(TestUri.REGISTER_URI)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto())))
            .andExpect(status().isUnauthorized());

        verifyNoInteractions(deviceRegistrationService);
    }

    @Test
    void registerDevice_shouldReturn403_whenRolesWrong() throws Exception {
        registerDevice(getAccessToken(DeviceType.MANAGER), deviceRegisterRequestDto())
            .andExpect(status().isForbidden());

        verifyNoInteractions(deviceRegistrationService);
    }

    // helpers

    private ResultActions registerDevice(
        String accessToken,
        DeviceRegisterRequestDto requestDto
    ) throws Exception {
        return mockMvc.perform(post(TestUri.REGISTER_URI)
            .header("Authorization", "Bearer " + accessToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(requestDto)));
    }

    private String getAccessToken(DeviceType deviceType) {
        return getAccessToken(deviceType.getClientId());
    }

    private String getAccessToken(String clientId) {
        return getAccessToken(clientId, "password");
    }

    private String getAccessToken(String clientId, String password) {
        Map<?, ?> response = RestClient.create()
            .post()
            .uri(
                keycloak.getAuthServerUrl()
                    + "/realms/mesync-test/protocol/openid-connect/token"
            )
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(
                "grant_type=password" +
                    "&client_id=" + clientId +
                    "&username=test-user" +
                    "&password=" + password
            )
            .retrieve()
            .body(Map.class);

        return (String) response.get("access_token");
    }

    private DeviceRegisterRequestDto deviceRegisterRequestDto() {
        return new DeviceRegisterRequestDto(
            "test device",
            "a".repeat(44),
            Map.of(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

}
