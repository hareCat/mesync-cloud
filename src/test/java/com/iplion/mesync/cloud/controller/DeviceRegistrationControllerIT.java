package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreMasterKeyRequestDto;
import com.iplion.mesync.cloud.controller.dto.StorePublicKeysRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.StoreInviteAuthRequest;
import com.iplion.mesync.cloud.security.auth.StoreMasterKeyAuthRequest;
import com.iplion.mesync.cloud.security.auth.StorePublicKeysAuthRequest;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
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

class DeviceRegistrationControllerIT extends BaseIT {
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
    void storeInvite_shouldReturn201CreatedAndStoreInviteInRedis() throws Exception {
        var context = TestDataFactory.createInviteContext();

        TestDataFactory.saveNewUserWithDevice(
            context,
            context.devicePublicId,
            context.publicKeyBytes,
            deviceRepository,
            userRepository
        );

        var requestDto = TestDataFactory.storeInviteRequestDto(context);

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
        assertThat(inviteData.getDeviceType()).isEqualTo(requestDto.deviceType());
        assertThat(inviteData.getBase64EncryptedMasterKey()).isNull();
        assertThat(inviteData.getKeyVersion()).isNull();
    }

    @Test
    void storePublicKeys_shouldReturn201CreatedAndStorePublicKeysInRedis() throws Exception {
        KeyPair invitedSigningKeyPair = TestCrypto.generateKeyPair();
        var context = TestDataFactory.createRegistrationContext(invitedSigningKeyPair);
        DeviceType invitedDeviceType = DeviceType.BROWSER;

        invitationService.createInvite(
            context.authId,
            context.inviteToken,
            invitedDeviceType
        );

        var requestDto = TestDataFactory.storePublicKeysRequestDto(
            context,
            invitedSigningKeyPair.getPrivate(),
            UUID.randomUUID()
        );

        mockMvc.perform(post(TestUri.PUBLIC_KEY_URI)
                .with(TestJwtBuilder.forDevice(context.authId, invitedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );

        assertThat(inviteData).isNotNull();
        assertThat(inviteData.getDeviceType()).isEqualTo(invitedDeviceType);
        assertThat(inviteData.getBase64EncryptionPublicKey()).isEqualTo(context.base64EncryptionPublicKey);
        assertThat(inviteData.getBase64SigningPublicKey()).isEqualTo(context.base64PublicKey);
        assertThat(inviteData.getBase64EncryptedMasterKey()).isNull();
        assertThat(inviteData.getKeyVersion()).isNull();
    }

    @Test
    void storeMasterKey_shouldReturn201CreatedAndStoreMasterKeyInRedis() throws Exception {
        KeyPair trustedDeviceKeyPair = TestCrypto.generateKeyPair();
        KeyPair invitedSigningKeyPair = TestCrypto.generateKeyPair();
        var context = TestDataFactory.createRegistrationContext(invitedSigningKeyPair);

        UUID trustedDevicePublicId = UUID.randomUUID();
        DeviceType trustedDeviceType = DeviceType.MOBILE;
        DeviceType invitedDeviceType = DeviceType.BROWSER;

        User trustedUser = TestDataFactory.saveNewUser(context.authId, userRepository);
        TestDataFactory.saveNewDevice(
            context,
            trustedDevicePublicId,
            trustedUser,
            trustedDeviceKeyPair.getPublic().getEncoded(),
            trustedDeviceType,
            "trusted device",
            deviceRepository
        );

        invitationService.createInvite(
            context.authId,
            context.inviteToken,
            invitedDeviceType
        );
        invitationService.storePublicKeys(
            context.authId,
            context.inviteToken,
            context.base64EncryptionPublicKey,
            context.base64PublicKey
        );

        var requestDto = TestDataFactory.storeMasterKeyRequestDto(
            context,
            trustedDevicePublicId,
            trustedDeviceKeyPair.getPrivate(),
            UUID.randomUUID()
        );

        mockMvc.perform(post(TestUri.MASTER_KEY_URI)
                .with(TestJwtBuilder.forDevice(context.authId, trustedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );

        assertThat(inviteData).isNotNull();
        assertThat(inviteData.getBase64EncryptionPublicKey()).isEqualTo(context.base64EncryptionPublicKey);
        assertThat(inviteData.getBase64SigningPublicKey()).isEqualTo(context.base64PublicKey);
        assertThat(inviteData.getBase64EncryptedMasterKey()).isEqualTo(context.encryptedMasterKey);
        assertThat(inviteData.getKeyVersion()).isEqualTo(context.keyVersion);
    }

    @Test
    void register_shouldReturn201CreatedAndConsumeReadyInvite() throws Exception {
        KeyPair trustedDeviceKeyPair = TestCrypto.generateKeyPair();
        KeyPair invitedSigningKeyPair = TestCrypto.generateKeyPair();
        var context = TestDataFactory.createRegistrationContext(invitedSigningKeyPair);

        UUID trustedDevicePublicId = UUID.randomUUID();
        DeviceType trustedDeviceType = DeviceType.MOBILE;
        DeviceType invitedDeviceType = DeviceType.BROWSER;

        User trustedUser = TestDataFactory.saveNewUser(context.authId, userRepository);
        TestDataFactory.saveNewDevice(
            context,
            trustedDevicePublicId,
            trustedUser,
            trustedDeviceKeyPair.getPublic().getEncoded(),
            trustedDeviceType,
            "trusted device",
            deviceRepository
        );

        invitationService.createInvite(
            context.authId,
            context.inviteToken,
            invitedDeviceType
        );
        invitationService.storePublicKeys(
            context.authId,
            context.inviteToken,
            context.base64EncryptionPublicKey,
            context.base64PublicKey
        );
        invitationService.storeMasterKey(
            context.authId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion
        );

        var requestDto = TestDataFactory.deviceRegisterRequestDto(context, invitedSigningKeyPair);

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .with(TestJwtBuilder.forDevice(context.authId, invitedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.deviceName").value(context.deviceName))
            .andExpect(jsonPath("$.encryptedMasterKey").value(context.encryptedMasterKey))
            .andExpect(jsonPath("$.keyVersion").value(context.keyVersion));

        List<Device> devices = deviceRepository.findActiveByUserAuthId(context.authId);
        assertThat(devices).hasSize(2);
        assertThat(devices)
            .extracting(Device::getName)
            .containsExactlyInAnyOrder("trusted device", context.deviceName);

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );
        assertThat(inviteData).isNull();
    }

    @Test
    void register_shouldCompleteAdditionalDeviceRegistrationThroughFourStepHttpFlow() throws Exception {
        KeyPair trustedDeviceKeyPair = TestCrypto.generateKeyPair();
        KeyPair invitedSigningKeyPair = TestCrypto.generateKeyPair();

        var context = TestDataFactory.createRegistrationContext(invitedSigningKeyPair);

        UUID trustedDevicePublicId = UUID.randomUUID();
        DeviceType trustedDeviceType = DeviceType.MOBILE;
        DeviceType invitedDeviceType = DeviceType.BROWSER;

        User trustedUser = TestDataFactory.saveNewUser(context.authId, userRepository);
        TestDataFactory.saveNewDevice(
            context,
            trustedDevicePublicId,
            trustedUser,
            trustedDeviceKeyPair.getPublic().getEncoded(),
            trustedDeviceType,
            "trusted device",
            deviceRepository
        );

        var inviteRequestDto = TestDataFactory.storeInviteRequestDto(
            context,
            trustedDevicePublicId,
            invitedDeviceType,
            trustedDeviceKeyPair.getPrivate(),
            UUID.randomUUID()
        );

        mockMvc.perform(post(TestUri.INVITE_URI)
                .with(TestJwtBuilder.forDevice(context.authId, trustedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(inviteRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        var publicKeysRequestDto = TestDataFactory.storePublicKeysRequestDto(
            context,
            invitedSigningKeyPair.getPrivate(),
            UUID.randomUUID()
        );

        mockMvc.perform(post(TestUri.PUBLIC_KEY_URI)
                .with(TestJwtBuilder.forDevice(context.authId, invitedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(publicKeysRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData inviteWithPublicKeys = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );
        assertThat(inviteWithPublicKeys).isNotNull();
        assertThat(inviteWithPublicKeys.getDeviceType()).isEqualTo(invitedDeviceType);
        assertThat(inviteWithPublicKeys.getBase64EncryptionPublicKey()).isEqualTo(context.base64EncryptionPublicKey);
        assertThat(inviteWithPublicKeys.getBase64SigningPublicKey()).isEqualTo(context.base64PublicKey);
        assertThat(inviteWithPublicKeys.getBase64EncryptedMasterKey()).isNull();
        assertThat(inviteWithPublicKeys.getKeyVersion()).isNull();

        var masterKeyRequestDto = TestDataFactory.storeMasterKeyRequestDto(
            context,
            trustedDevicePublicId,
            trustedDeviceKeyPair.getPrivate(),
            UUID.randomUUID()
        );

        mockMvc.perform(post(TestUri.MASTER_KEY_URI)
                .with(TestJwtBuilder.forDevice(context.authId, trustedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("devices.invite")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(masterKeyRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.expiresAt").exists());

        DeviceInviteData readyInvite = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );
        assertThat(readyInvite).isNotNull();
        assertThat(readyInvite.getBase64EncryptedMasterKey()).isEqualTo(context.encryptedMasterKey);
        assertThat(readyInvite.getKeyVersion()).isEqualTo(context.keyVersion);

        var registerRequestDto = TestDataFactory.deviceRegisterRequestDto(context, invitedSigningKeyPair);

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .with(TestJwtBuilder.forDevice(context.authId, invitedDeviceType)
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.devicePublicId").exists())
            .andExpect(jsonPath("$.deviceName").value(context.deviceName))
            .andExpect(jsonPath("$.encryptedMasterKey").value(context.encryptedMasterKey))
            .andExpect(jsonPath("$.keyVersion").value(context.keyVersion));

        List<User> users = userRepository.findAll();
        assertThat(users).hasSize(1);

        List<Device> devices = deviceRepository.findActiveByUserAuthId(context.authId);
        assertThat(devices).hasSize(2);

        Device invitedDevice = devices.stream()
            .filter(d -> !d.getPublicId().equals(trustedDevicePublicId))
            .filter(d -> d.getDeviceType() == invitedDeviceType)
            .findFirst()
            .orElseThrow();
        assertThat(invitedDevice.getName()).isEqualTo(context.deviceName);
        assertThat(invitedDevice.getExtras()).isEqualTo(context.extras);
        assertThat(invitedDevice.getPublicKeyBytes()).isEqualTo(context.publicKeyBytes);

        DeviceInviteData consumedInvite = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );
        assertThat(consumedInvite).isNull();
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
            newDeviceType
        );
        invitationService.storePublicKeys(
            context.authId,
            context.inviteToken,
            context.base64EncryptionPublicKey,
            context.base64PublicKey
        );
        invitationService.storeMasterKey(
            context.authId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion
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
            context.deviceType
        );
        invitationService.storePublicKeys(
            context.authId,
            context.inviteToken,
            context.base64EncryptionPublicKey,
            context.base64PublicKey
        );
        invitationService.storeMasterKey(
            context.authId,
            context.inviteToken,
            context.encryptedMasterKey,
            context.keyVersion
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

    private static class TestDataFactory {
        public static class TestContext {
            UUID authId;
            UUID devicePublicId;
            String deviceName;
            DeviceType deviceType;
            String inviteToken;
            UUID nonce;
            String encryptedMasterKey;
            Integer keyVersion;
            byte[] publicKeyBytes;
            String base64Signature;
            String base64PublicKey;
            String base64EncryptionPublicKey;
            Map<String, String> extras;
        }

        public static TestContext createInviteContext() throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.prepareContext(keyPair);
            byte[] payload = new StoreInviteAuthRequest(
                null,
                context.nonce,
                context.devicePublicId,
                context.inviteToken,
                context.deviceType,
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
                context.deviceName,
                context.extras,
                context.inviteToken
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
            context.inviteToken = TestModelFactory.inviteToken();
            context.nonce = UUID.randomUUID();
            context.encryptedMasterKey = "a".repeat(32);
            context.keyVersion = 1;
            context.publicKeyBytes = keyPair.getPublic().getEncoded();
            context.base64PublicKey = Base64.getEncoder().encodeToString(context.publicKeyBytes);
            context.base64EncryptionPublicKey = "b".repeat(44);
            context.extras = Map.of("platform", "android");

            return context;
        }

        public static void saveNewUserWithDevice(
            TestContext context,
            UUID devicePublicId,
            byte[] publicKeyBytes,
            DeviceType deviceType,
            DeviceRepository deviceRepository,
            UserRepository userRepository
        ) {
            User user = saveNewUser(context.authId, userRepository);
            saveNewDevice(context, devicePublicId, user, publicKeyBytes, deviceType, context.deviceName, deviceRepository);
        }

        public static void saveNewUserWithDevice(
            TestContext context,
            UUID devicePublicId,
            byte[] publicKeyBytes,
            DeviceRepository deviceRepository,
            UserRepository userRepository
        ) {
            saveNewUserWithDevice(
                context,
                devicePublicId,
                publicKeyBytes,
                context.deviceType,
                deviceRepository,
                userRepository
            );
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
            DeviceType deviceType,
            String deviceName,
            DeviceRepository deviceRepository
        ) {
            Device device = new Device();
            device.setPublicId(devicePublicId);
            device.setUser(user);
            device.setDeviceType(deviceType);
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

        public static StoreInviteRequestDto storeInviteRequestDto(TestContext context) {
            return new StoreInviteRequestDto(
                context.devicePublicId,
                context.inviteToken,
                context.keyVersion,
                context.deviceType,
                context.nonce,
                context.base64Signature
            );
        }

        public static StoreInviteRequestDto storeInviteRequestDto(
            TestContext context,
            UUID devicePublicId,
            DeviceType deviceType,
            PrivateKey privateKey,
            UUID nonce
        ) throws GeneralSecurityException {
            String base64Signature = sign(privateKey, new StoreInviteAuthRequest(
                null,
                nonce,
                devicePublicId,
                context.inviteToken,
                deviceType,
                context.keyVersion
            ).payload());

            return new StoreInviteRequestDto(
                devicePublicId,
                context.inviteToken,
                context.keyVersion,
                deviceType,
                nonce,
                base64Signature
            );
        }

        public static StorePublicKeysRequestDto storePublicKeysRequestDto(
            TestContext context,
            PrivateKey privateKey,
            UUID nonce
        ) throws GeneralSecurityException {
            byte[] payload = new StorePublicKeysAuthRequest(
                null,
                nonce,
                context.base64PublicKey,
                context.inviteToken,
                context.base64EncryptionPublicKey
            ).payload();

            return new StorePublicKeysRequestDto(
                context.inviteToken,
                context.base64EncryptionPublicKey,
                context.base64PublicKey,
                nonce,
                sign(privateKey, payload)
            );
        }

        public static StoreMasterKeyRequestDto storeMasterKeyRequestDto(
            TestContext context,
            UUID devicePublicId,
            PrivateKey privateKey,
            UUID nonce
        ) throws GeneralSecurityException {
            byte[] payload = new StoreMasterKeyAuthRequest(
                null,
                nonce,
                devicePublicId,
                context.inviteToken,
                context.encryptedMasterKey,
                context.keyVersion
            ).payload();

            return new StoreMasterKeyRequestDto(
                devicePublicId,
                context.inviteToken,
                context.encryptedMasterKey,
                context.keyVersion,
                nonce,
                sign(privateKey, payload)
            );
        }

        private static String sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
            return Base64.getEncoder().encodeToString(
                TestCrypto.sign(privateKey, payload)
            );
        }

    }

}
