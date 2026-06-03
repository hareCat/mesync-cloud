package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.redis.RedisKeys;
import com.iplion.mesync.cloud.security.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.service.InvitationService;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestUri;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    JdbcTemplate jdbcTemplate;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @AfterEach
    void cleanUp() {
        jdbcTemplate.execute("""
                TRUNCATE TABLE devices, users
                RESTART IDENTITY
                CASCADE
            """);

        try (var connection = Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection()) {
            connection.serverCommands().flushDb();
        }
    }

    @Test
    void saveInvite_shouldReturn201CreatedAndStoreInviteInRedis() throws Exception {
        TestContext context = TestDataFactory.createInviteContext(TestCrypto.generateKeyPair());

        TestDataFactory.saveNewUserWithDevice(
            context,
            context.devicePublicId,
            context.publicKeyBytes,
            deviceRepository,
            userRepository
        );

        var requestDto = new SaveInviteRequestDto(
            context.devicePublicId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion,
            context.deviceType,
            context.nonce,
            context.base64Signature
        );

        mockMvc.perform(post(TestUri.INVITE_URI)
                .with(TestJwtBuilder.forDevice(context.authId, context.deviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData inviteData = redisSecurityStore.getAndDelete(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );

        assertThat(inviteData).isNotNull();
        assertThat(inviteData.deviceType()).isEqualTo(requestDto.deviceType());
        assertThat(inviteData.encryptedMasterKey()).isEqualTo(requestDto.encryptedMasterKey());
        assertThat(inviteData.keyVersion()).isEqualTo(requestDto.keyVersion());
    }

    @Test
    void registerDevice_shouldReturn201CreatedAndGenerateNewName_whenNameAlreadyExists() throws Exception {
        KeyPair newDeviceKeyPair = TestCrypto.generateKeyPair();

        TestContext context = TestDataFactory.createRegistrationContext(newDeviceKeyPair);

        DeviceType newDeviceType = DeviceType.BROWSER;
        String deviceRequiredName = context.deviceName;
        String deviceGeneratedName = deviceRequiredName + "-" + newDeviceType.name().toLowerCase();

        TestDataFactory.saveNewUserWithDevice(
            context,
            UUID.randomUUID(),
            TestCrypto.generateKeyPair().getPublic().getEncoded(),
            deviceRepository,
            userRepository
        );

        var requestDto = new DeviceRegisterRequestDto(
            context.deviceName,
            Base64.getEncoder().encodeToString(newDeviceKeyPair.getPublic().getEncoded()),
            context.extras,
            context.inviteToken,
            context.nonce,
            context.base64Signature
        );

        invitationService.createInvite(
            context.authId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion,
            newDeviceType
        );

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .with(TestJwtBuilder.forDevice(context.authId, newDeviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.devicePublicId").exists())
            .andExpect(jsonPath("$.deviceName").value(deviceGeneratedName))
            .andExpect(jsonPath("$.encryptedMasterKey").value(context.encryptedMasterKey))
            .andExpect(jsonPath("$.keyVersion").value(context.keyVersion));

        DeviceInviteData inviteData = redisSecurityStore.getAndDelete(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );

        List<User> users = userRepository.findAll();
        assertThat(users).hasSize(1);
        User user = users.get(0);

        List<Device> devices = deviceRepository.findActiveByUserAuthId(context.authId);
        assertThat(devices).hasSize(2);
        Device savedDevice = devices.stream()
            .filter(d -> d.getName().equals(deviceGeneratedName))
            .findFirst()
            .orElseThrow();

        assertThat(devices)
            .extracting(Device::getName)
            .containsExactlyInAnyOrder(deviceRequiredName, deviceGeneratedName);
        assertThat(savedDevice.getName()).isEqualTo(deviceGeneratedName);
        assertThat(savedDevice.getDeviceType()).isEqualTo(newDeviceType);
        assertThat(savedDevice.getExtras()).isEqualTo(requestDto.extras());
        assertThat(savedDevice.getPublicKeyBytes()).isEqualTo(context.publicKeyBytes);
        assertThat(user.getAuthId()).isEqualTo(context.authId);
        assertThat(inviteData).isNull();
    }

    @Test
    void registerDevice_shouldReturn403Forbidden_whenPublicKeyInvalid() throws Exception {
        TestContext context = TestDataFactory.createRegistrationContext(TestCrypto.generateKeyPair());

        var requestDto = new DeviceRegisterRequestDto(
            context.deviceName,
            Base64.getEncoder().encodeToString(TestCrypto.generateKeyPair().getPublic().getEncoded()),
            context.extras,
            context.inviteToken,
            context.nonce,
            context.base64Signature
        );

        invitationService.createInvite(
            context.authId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion,
            context.deviceType
        );

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .with(TestJwtBuilder.forDevice(context.authId, context.deviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.detail", containsString("valid")));

        List<User> users = userRepository.findAll();
        assertThat(users).hasSize(0);

        List<Device> devices = deviceRepository.findActiveByUserAuthId(context.authId);
        assertThat(devices).hasSize(0);

        DeviceInviteData inviteData = redisSecurityStore.getAndDelete(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );

        assertThat(inviteData).isNotNull();
    }

    // helpers ------------------------

    public static class TestContext {
        UUID authId;
        UUID devicePublicId;
        String deviceName;
        DeviceType deviceType;
        UUID inviteToken;
        UUID nonce;
        String encryptedMasterKey;
        Integer keyVersion;
        byte[] publicKeyBytes;
        String base64Signature;
        String base64PublicKey;
        Map<String, String> extras;
    }

    private static class TestDataFactory {
        public static TestContext createInviteContext(KeyPair keyPair) throws GeneralSecurityException {
            TestContext context = TestDataFactory.createContext(keyPair);
            byte[] payload = new SaveInviteAuthRequest(
                null,
                null,
                context.nonce,
                context.devicePublicId,
                context.inviteToken,
                context.encryptedMasterKey,
                context.keyVersion
            ).payload();
            context.base64Signature = Base64.getEncoder().encodeToString(
                TestCrypto.sign(keyPair.getPrivate(), payload)
            );

            return context;
        }

        public static TestContext createRegistrationContext(KeyPair keyPair) throws GeneralSecurityException {
            TestContext context = TestDataFactory.createContext(keyPair);
            byte[] payload = new RegistrationAuthRequest(
                null,
                null,
                context.nonce,
                context.base64PublicKey,
                context.inviteToken
            ).payload();
            context.base64Signature = Base64.getEncoder().encodeToString(
                TestCrypto.sign(keyPair.getPrivate(), payload)
            );

            return context;
        }

        private static TestContext createContext(KeyPair keyPair) {
            var context = new TestContext();
            context.authId = UUID.randomUUID();
            context.devicePublicId = UUID.randomUUID();
            context.deviceName = "test name";
            context.deviceType = DeviceType.MOBILE;
            context.inviteToken = UUID.randomUUID();
            context.nonce = UUID.randomUUID();
            context.encryptedMasterKey = "a".repeat(32);
            context.keyVersion = 2;
            context.publicKeyBytes = keyPair.getPublic().getEncoded();
            context.base64PublicKey = Base64.getEncoder().encodeToString(context.publicKeyBytes);
            context.extras = Map.of("platform", "android");

            return context;
        }

        public static void saveNewUserWithDevice(
            TestContext context,
            UUID devicePublicId,
            byte[] publicKeyBytes,
            DeviceRepository deviceRepository,
            UserRepository userRepository
        ) {
            User user = new User();
            user.setAuthId(context.authId);
            userRepository.saveAndFlush(user);

            Device device = new Device();
            device.setPublicId(devicePublicId);
            device.setUser(user);
            device.setDeviceType(context.deviceType);
            device.setName(context.deviceName);
            device.setPublicKeyBytes(publicKeyBytes);
            device.setKeyCreatedAt(Instant.now());
            device.setLastActiveAt(Instant.now());
            device.setExtras(context.extras);
            deviceRepository.saveAndFlush(device);
        }

    }

}

