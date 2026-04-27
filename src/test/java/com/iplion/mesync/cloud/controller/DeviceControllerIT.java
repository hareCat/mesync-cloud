package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.database.rider.core.api.configuration.DBUnit;
import com.github.database.rider.core.api.dataset.DataSet;
import com.github.database.rider.spring.api.DBRider;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.infrastructure.redis.RedisKeys;
import com.iplion.mesync.cloud.infrastructure.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.service.InvitationService;
import com.iplion.mesync.cloud.service.RegistrationCryptoService;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DBRider
@DBUnit(caseSensitiveTableNames = true)
class DeviceControllerIT extends BaseIT {
    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    InvitationService invitationService;

    @Autowired
    private RedisSecurityStore redisSecurityStore;

    @Autowired
    DeviceRepository deviceRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @MockitoBean
    JwtDecoder jwtDecoder;

    @MockitoBean
    RegistrationCryptoService registrationCryptoService;

    private static final String REGISTER_URI = "/api/v1/devices/register";
    private static final String INVITE_URI = "/api/v1/devices/invite";

    private static String base64PublicKey;

    @BeforeAll
    static void init() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        byte[] publicKeyBytes = generator.generateKeyPair().getPublic().getEncoded();
        base64PublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    @BeforeEach
    void cleanRedis() {
        try (var conn = redisConnectionFactory.getConnection()) {
            conn.serverCommands().flushAll();
        }
    }

    @Test
    void saveInvite_shouldReturn201Created_andStoreInviteInRedis() throws Exception {
        UUID authId = UUID.randomUUID();
        UUID inviteToken = UUID.randomUUID();
        String testPublicKey = "a".repeat(32);
        DeviceType deviceType = DeviceType.MOBILE;

        DeviceInviteRequestDto deviceInviteRequestDto = new DeviceInviteRequestDto(
            inviteToken,
            testPublicKey,
            deviceType
        );

        mockMvc.perform(post(INVITE_URI)
                .with(TestJwtBuilder.forDevice(authId, deviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceInviteRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(authId, inviteToken),
            DeviceInviteData.class
        );

        assertThat(inviteData).isNotNull();
        assertThat(inviteData.deviceType()).isEqualTo(deviceType);
        assertThat(inviteData.encryptedMasterKey()).isEqualTo(testPublicKey);
    }

    @Test
    void saveInvite_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        UUID inviteToken = UUID.randomUUID();
        String testPublicKey = "a".repeat(32);
        DeviceType deviceType = DeviceType.MOBILE;

        DeviceInviteRequestDto deviceInviteRequestDto = new DeviceInviteRequestDto(
            inviteToken,
            testPublicKey,
            deviceType
        );

        mockMvc.perform(post(INVITE_URI)
                .with(TestJwtBuilder.forDevice(UUID.randomUUID(), deviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceInviteRequestDto)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.title").exists())
            .andExpect(jsonPath("$.instance").exists());
    }

    @Test
    @DataSet(cleanBefore = true)
    void registerDevice_shouldReturn201Created_andSaveNewUserWithNewDevice() throws Exception {
        UUID authId = UUID.randomUUID();
        UUID inviteToken = UUID.randomUUID();
        DeviceType deviceType = DeviceType.MOBILE;
        String deviceName = "test device";

        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            deviceName,
            deviceType,
            base64PublicKey,
            Map.of("platform", "android"),
            inviteToken,
            "base64Signature"
        );

        when(registrationCryptoService.verifyAngExtractPublicKeyBytes(any())).thenReturn(new byte[44]);

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.forDevice(authId, deviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.deviceId").exists())
            .andExpect(jsonPath("$.deviceName").value(deviceName))
            .andExpect(jsonPath("$.encryptedMasterKey").value(nullValue()));

        List<User> users = userRepository.findAll();
        assertThat(users).hasSize(1);
        User user = users.get(0);

        List<Device> devices = deviceRepository.findActiveByUserAuthId(authId);
        assertThat(devices).hasSize(1);
        Device device = devices.get(0);

        assertThat(device.getName()).isEqualTo(deviceRegisterRequestDto.deviceName());
        assertThat(device.getDeviceType()).isEqualTo(deviceRegisterRequestDto.deviceType());
        assertThat(device.getExtras()).isEqualTo(deviceRegisterRequestDto.extras());
        assertThat(device.getPublicKey()).isNotNull();
        assertThat(user.getAuthId()).isEqualTo(authId);

    }

    @Test
    @DataSet(value = "datasets/deviceController/register/before.yaml", cleanBefore = true)
    void registerDevice_shouldReturn201Created_andGenerateNewName_whenNameAlreadyExists() throws Exception {
        UUID authId = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
        UUID inviteToken = UUID.randomUUID();
        DeviceType deviceType = DeviceType.BROWSER;
        String deviceRequiredName = "test device";
        String deviceGeneratedName = deviceRequiredName + "-" + deviceType.name().toLowerCase();
        String encryptedMasterKey = "encryptedMasterKey";

        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            deviceRequiredName,
            deviceType,
            base64PublicKey,
            Map.of("platform", "android"),
            inviteToken,
            "base64Signature"
        );

        invitationService.createInvite(authId, inviteToken, encryptedMasterKey, deviceType);

        when(registrationCryptoService.verifyAngExtractPublicKeyBytes(any())).thenReturn(new byte[44]);

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.forDevice(authId, deviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.deviceId").exists())
            .andExpect(jsonPath("$.deviceName").value(deviceGeneratedName))
            .andExpect(jsonPath("$.encryptedMasterKey").value(encryptedMasterKey));

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(authId, inviteToken),
            DeviceInviteData.class
        );

        List<User> users = userRepository.findAll();
        assertThat(users).hasSize(1);
        User user = users.get(0);

        List<Device> devices = deviceRepository.findActiveByUserAuthId(authId);
        assertThat(devices).hasSize(2);
        Device savedDevice = devices.stream()
            .filter(d -> d.getName().equals(deviceGeneratedName))
            .findFirst()
            .orElseThrow();

        assertThat(devices)
            .extracting(Device::getName)
            .containsExactlyInAnyOrder(deviceRequiredName, deviceGeneratedName);
        assertThat(savedDevice.getName()).isEqualTo(deviceGeneratedName);
        assertThat(savedDevice.getDeviceType()).isEqualTo(deviceRegisterRequestDto.deviceType());
        assertThat(savedDevice.getExtras()).isEqualTo(deviceRegisterRequestDto.extras());
        assertThat(savedDevice.getPublicKey()).isNotNull();
        assertThat(user.getAuthId()).isEqualTo(authId);
        assertThat(inviteData).isNull();
    }

    @Test
    void registerDevice_shouldReturn403Forbidden_whenAuthoritiesWrong() throws Exception {
        DeviceType deviceType = DeviceType.BROWSER;

        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            "test device",
            deviceType,
            base64PublicKey,
            Map.of("platform", "android"),
            UUID.randomUUID(),
            "base64Signature"
        );

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.forDevice(UUID.randomUUID(), deviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.remove")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isForbidden());
    }

    @Test
    void registerDevice_shouldReturn401Unauthorized_whenNoJwt() throws Exception {
        mockMvc.perform(post(REGISTER_URI))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    void registerDevice_shouldReturn401Unauthorized_whenInvalidJwt() throws Exception {
        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            "test device",
            DeviceType.MOBILE,
            base64PublicKey,
            Map.of("platform", "android"),
            UUID.randomUUID(),
            "base64Signature"
        );

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.custom().buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DataSet(value = "datasets/deviceController/register/before.yaml", cleanBefore = true)
    void registerDevice_shouldReturn400BadRequest_whenInviteNotExist() throws Exception {
        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            "test device",
            DeviceType.MOBILE,
            base64PublicKey,
            Map.of("platform", "android"),
            UUID.randomUUID(),
            "base64Signature"
        );

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.forDevice(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"), DeviceType.MOBILE).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isBadRequest());
    }

    @Test
    @DataSet(value = "datasets/deviceController/register/before.yaml", cleanBefore = true)
    void registerDevice_shouldReturn400BadRequest_whenInviteDeviceAndJwtDeviceMismatch() throws Exception {
        UUID authId = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
        UUID inviteToken = UUID.randomUUID();
        DeviceType inviteDeviceType = DeviceType.BROWSER;
        DeviceType requestDeviceType = DeviceType.MOBILE;

        DeviceRegisterRequestDto deviceRegisterRequestDto = new DeviceRegisterRequestDto(
            "test device",
            requestDeviceType,
            base64PublicKey,
            Map.of("platform", "android"),
            inviteToken,
            "base64Signature"
        );

        invitationService.createInvite(authId, inviteToken, "encryptedMasterKey", inviteDeviceType);

        mockMvc.perform(post(REGISTER_URI)
                .with(TestJwtBuilder.forDevice(authId, requestDeviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(deviceRegisterRequestDto)))
            .andExpect(status().isBadRequest());
    }
}

