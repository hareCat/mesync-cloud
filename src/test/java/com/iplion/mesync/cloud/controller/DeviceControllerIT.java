package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.auth.DeviceRevokeAuthRequest;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
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
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class DeviceControllerIT extends BaseIT {
    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

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
    void revoke_shouldRevokeDeviceAndInvalidateDeviceAuthCache() throws Exception {
        UUID targetDevicePublicId = UUID.randomUUID();
        var context = TestDataFactory.createRevocationContext(targetDevicePublicId);
        var requestDto = TestDataFactory.deviceRevokeRequestDto(context, targetDevicePublicId);
        PublicKey targetDevicePublicKey = TestCrypto.generateKeyPair().getPublic();

        User user = TestDataFactory.saveNewUser(
            context.authId,
            userRepository
        );
        Device trustedDevice = TestDataFactory.saveNewDevice(
            context.devicePublicId,
            user,
            context.publicKeyBytes,
            context.deviceName,
            deviceRepository
        );
        Device targetDevice = TestDataFactory.saveNewDevice(
            targetDevicePublicId,
            user,
            targetDevicePublicKey.getEncoded(),
            "target " + context.deviceName,
            deviceRepository
        );
        deviceAuthCache.put(targetDevicePublicId, new DeviceAuthData(
            targetDevice.getId(),
            targetDevice.getPublicId(),
            user.getAuthId(),
            targetDevice.getDeviceType(),
            targetDevicePublicKey
        ));
        userAuthCache.put(user.getAuthId(), new UserAuthData(
            user.getId(),
            user.getAuthId(),
            user.getKeyVersion()
        ));

        mockMvc.perform(post(TestUri.REVOKE_URI)
                .with(TestJwtBuilder.forDevice(context.authId, trustedDevice.getDeviceType())
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
            UUID nonce;
            Integer keyVersion;
            byte[] publicKeyBytes;
            String base64Signature;
            String base64PublicKey;
            Map<String, String> extras;
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
            context.nonce = UUID.randomUUID();
            context.keyVersion = 1;
            context.publicKeyBytes = keyPair.getPublic().getEncoded();
            context.base64PublicKey = Base64.getEncoder().encodeToString(context.publicKeyBytes);
            context.extras = Map.of("platform", "android");

            return context;
        }

        public static User saveNewUser(UUID authId, UserRepository userRepository) {
            User user = TestModelFactory.user(authId);
            userRepository.saveAndFlush(user);

            return user;
        }

        public static Device saveNewDevice(
            UUID devicePublicId,
            User user,
            byte[] publicKeyBytes,
            String deviceName,
            DeviceRepository deviceRepository
        ) {
            Device device = new Device();
            device.setPublicId(devicePublicId);
            device.setUser(user);
            device.setDeviceType(DeviceType.MOBILE);
            device.setName(deviceName);
            device.setPublicKeyBytes(publicKeyBytes);
            device.setKeyCreatedAt(Instant.now());
            device.setLastActiveAt(Instant.now());
            device.setExtras(Map.of("platform", "android"));
            deviceRepository.saveAndFlush(device);

            return device;
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
