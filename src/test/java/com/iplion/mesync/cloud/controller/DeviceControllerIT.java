package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.auth.DeviceRevokeAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.service.InvitationService;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
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
import java.security.PrivateKey;
import java.security.PublicKey;
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

    @Autowired
    private Cache<UUID, DeviceAuthData> deviceAuthCache;

    @Autowired
    private Cache<UUID, UserAuthData> userAuthCache;

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
        var context = TestDataFactory.createInviteContext();

        TestDataFactory.saveNewUserWithDevice(
            context,
            context.devicePublicId,
            context.publicKeyBytes,
            deviceRepository,
            userRepository
        );

        var requestDto = TestDataFactory.saveInviteRequestDto(context);

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
    void register_shouldReturn201CreatedAndGenerateNewName_whenNameAlreadyExists() throws Exception {
        KeyPair newDeviceKeyPair = TestCrypto.generateKeyPair();

        var context = TestDataFactory.createRegistrationContext(newDeviceKeyPair);

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

        var requestDto = TestDataFactory.deviceRegisterRequestDto(context, newDeviceKeyPair);

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
    void register_shouldReturn403Forbidden_whenPublicKeyInvalid() throws Exception {
        var context = TestDataFactory.createRegistrationContext(TestCrypto.generateKeyPair());

        var requestDto = TestDataFactory.deviceRegisterRequestDto(context, TestCrypto.generateKeyPair());

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

    @Test
    void revoke_shouldRevokeDeviceAndInvalidateDeviceAuthCache() throws Exception {
        UUID targetDevicePublicId = UUID.randomUUID();
        var context = TestDataFactory.createRevocationContext(targetDevicePublicId);
        var requestDto = TestDataFactory.deviceRevokeRequestDto(context, targetDevicePublicId);
        PublicKey targetDevicePublicKey = TestCrypto.generateKeyPair().getPublic();

        User user = TestDataFactory.saveNewUser(
            context.authId,
            userRepository
        );
        TestDataFactory.saveNewDevice(
            context,
            context.devicePublicId,
            user,
            context.publicKeyBytes,
            context.deviceName,
            deviceRepository
        );
        Device targetDevice = TestDataFactory.saveNewDevice(
            context,
            targetDevicePublicId,
            user,
            targetDevicePublicKey.getEncoded(),
            "target " + context.deviceName,
            deviceRepository
        );
        deviceAuthCache.put(targetDevicePublicId, new DeviceAuthData(
            targetDevice.getId(),
            targetDevice.getPublicId(),
            targetDevice.getDeviceType(),
            targetDevicePublicKey
        ));
        userAuthCache.put(user.getAuthId(), new UserAuthData(
            user.getId(),
            user.getAuthId(),
            user.getKeyVersion()
        ));

        mockMvc.perform(post(TestUri.REVOKE_URI)
                .with(TestJwtBuilder.forDevice(context.authId, context.deviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.revoke")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.revokedDevicePublicId").value(targetDevicePublicId.toString()))
            .andExpect(jsonPath("$.revokedAt").isNotEmpty());

        assertThat(deviceAuthCache.getIfPresent(targetDevicePublicId)).isNull();

        Device revokedDevice = deviceRepository.findById(targetDevice.getId()).get();
        assertThat(revokedDevice.getRevokedAt()).isNotNull();
    }

    // helpers ------------------------

    private static class TestDataFactory {
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

        public static TestContext createInviteContext() throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.prepareContext(keyPair);
            byte[] payload = new SaveInviteAuthRequest(
                null,
                context.nonce,
                context.devicePublicId,
                context.inviteToken,
                context.encryptedMasterKey,
                context.keyVersion
            ).payload();
            context.base64Signature = sign(keyPair.getPrivate(), payload);

            return context;
        }

        public static TestContext createRegistrationContext(KeyPair keyPair) throws GeneralSecurityException {
            TestContext context = TestDataFactory.prepareContext(keyPair);
            byte[] payload = new RegistrationAuthRequest(
                null,
                context.nonce,
                context.base64PublicKey,
                context.inviteToken
            ).payload();
            context.base64Signature = sign(keyPair.getPrivate(), payload);

            return context;
        }

        public static TestContext createRevocationContext(UUID targetDevicePublicId) throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.prepareContext(keyPair);
            byte[] payload = new DeviceRevokeAuthRequest(
                null,
                context.nonce,
                context.devicePublicId,
                targetDevicePublicId,
                context.keyVersion + 1
            ).payload();
            context.base64Signature = sign(keyPair.getPrivate(), payload);

            return context;
        }

        private static TestContext prepareContext(KeyPair keyPair) {
            var context = new TestContext();
            context.authId = UUID.randomUUID();
            context.devicePublicId = UUID.randomUUID();
            context.deviceName = "test name";
            context.deviceType = DeviceType.MOBILE;
            context.inviteToken = UUID.randomUUID();
            context.nonce = UUID.randomUUID();
            context.encryptedMasterKey = "a".repeat(32);
            context.keyVersion = 1;
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
            User user = saveNewUser(context.authId, userRepository);
            saveNewDevice(context, devicePublicId, user, publicKeyBytes, context.deviceName, deviceRepository);
        }

        public static User saveNewUser(UUID authId, UserRepository userRepository) {
            User user = TestModelFactory.user(authId);
            userRepository.saveAndFlush(user);

            return user;
        }

        public static Device saveNewDevice(
            TestContext context,
            UUID devicePublicId,
            User user,
            byte[] publicKeyBytes,
            String deviceName,
            DeviceRepository deviceRepository
        ) {
            Device device = new Device();
            device.setPublicId(devicePublicId);
            device.setUser(user);
            device.setDeviceType(context.deviceType);
            device.setName(deviceName);
            device.setPublicKeyBytes(publicKeyBytes);
            device.setKeyCreatedAt(Instant.now());
            device.setLastActiveAt(Instant.now());
            device.setExtras(context.extras);
            deviceRepository.saveAndFlush(device);

            return device;
        }

        public static DeviceRegisterRequestDto deviceRegisterRequestDto(TestContext context, KeyPair keyPair) {
            return new DeviceRegisterRequestDto(
                context.deviceName,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                context.extras,
                context.inviteToken,
                context.nonce,
                context.base64Signature
            );
        }

        public static SaveInviteRequestDto saveInviteRequestDto(TestContext context) {
            return new SaveInviteRequestDto(
                context.devicePublicId,
                context.inviteToken,
                context.encryptedMasterKey,
                context.keyVersion,
                context.deviceType,
                context.nonce,
                context.base64Signature
            );
        }

        public static DeviceRevokeRequestDto deviceRevokeRequestDto(TestContext context, UUID targetDevicePublicId) {
            return new DeviceRevokeRequestDto(
                context.devicePublicId,
                targetDevicePublicId,
                true,
                context.keyVersion + 1,
                context.nonce,
                context.base64Signature
            );
        }

        private static String sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
            return Base64.getEncoder().encodeToString(
                TestCrypto.sign(privateKey, payload)
            );
        }

    }

}
