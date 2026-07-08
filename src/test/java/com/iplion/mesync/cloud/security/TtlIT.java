package com.iplion.mesync.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.MessageSyncRequestDto;
import com.iplion.mesync.cloud.controller.dto.StoreInviteRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.request.MessageSyncAuthRequest;
import com.iplion.mesync.cloud.security.request.StoreInviteAuthRequest;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TtlIT extends BaseIT {
    private static final Duration TTL_WAIT = Duration.ofSeconds(2);

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
    RedisTemplate<String, Object> redisTemplate;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("app.registration.invite-cooldown", () -> "1s");
        registry.add("app.registration.nonce-ttl", () -> "1s");
        registry.add("app.registration.rate-limit-ttl", () -> "1s");
        registry.add("app.registration.attempts", () -> "2");
        registry.add("app.auth.nonce-ttl", () -> "1s");
        registry.add("app.auth.rate-limit-ttl", () -> "1s");
        registry.add("app.auth.attempts", () -> "2");
    }

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
    void inviteCooldown_shouldRejectSecondInviteUntilTtlExpires() throws Exception {
        DeviceContext context = saveUserWithDevice();

        storeInvite(context, "012345", UUID.randomUUID())
            .andExpect(status().isCreated());

        storeInvite(context, "123456", UUID.randomUUID())
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.detail", containsString("such request every")));

        await().atMost(TTL_WAIT).untilAsserted(() -> storeInvite(context, "234567", UUID.randomUUID())
            .andExpect(status().isCreated()));
    }

    @Test
    void authNonce_shouldRejectReplayUntilTtlExpires() throws Exception {
        DeviceContext context = saveUserWithDevice();
        UUID nonce = UUID.randomUUID();
        MessageSyncRequestDto request = messageSyncRequestDto(context, nonce);

        sync(context, request)
            .andExpect(status().isOk());

        sync(context, request)
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.detail").value("Replay request detected"));

        await().atMost(TTL_WAIT).untilAsserted(() -> sync(context, request)
            .andExpect(status().isOk()));
    }

    @Test
    void authRateLimit_shouldRejectRequestsUntilTtlExpires() throws Exception {
        DeviceContext context = saveUserWithDevice();

        sync(context, messageSyncRequestDto(context, UUID.randomUUID()))
            .andExpect(status().isOk());
        sync(context, messageSyncRequestDto(context, UUID.randomUUID()))
            .andExpect(status().isOk());

        sync(context, messageSyncRequestDto(context, UUID.randomUUID()))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.detail").value("Too many requests"));

        await().atMost(TTL_WAIT).untilAsserted(() -> sync(context, messageSyncRequestDto(context, UUID.randomUUID()))
            .andExpect(status().isOk()));
    }

    @Test
    void registrationRateLimit_shouldRejectRequestsUntilTtlExpires() throws Exception {
        UUID authId = UUID.randomUUID();

        registerWithInvalidPublicKey(authId, UUID.randomUUID())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.detail").value("Cryptography data is not valid"));
        registerWithInvalidPublicKey(authId, UUID.randomUUID())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.detail").value("Cryptography data is not valid"));

        registerWithInvalidPublicKey(authId, UUID.randomUUID())
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.detail").value("Too many requests"));

        await().atMost(TTL_WAIT).untilAsserted(() -> registerWithInvalidPublicKey(authId, UUID.randomUUID())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.detail").value("Cryptography data is not valid")));
    }

    @Test
    void registrationNonce_shouldRejectReplayUntilTtlExpires() throws Exception {
        UUID authId = UUID.randomUUID();
        UUID nonce = UUID.randomUUID();

        registerWithInvalidPublicKey(authId, nonce)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.detail").value("Cryptography data is not valid"));

        registerWithInvalidPublicKey(authId, nonce)
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.detail").value("Replay request detected"));

        await().atMost(TTL_WAIT).untilAsserted(() -> registerWithInvalidPublicKey(authId, nonce)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.detail").value("Cryptography data is not valid")));
    }

    // --------------------------- helpers --------------------------

    private ResultActions storeInvite(
        DeviceContext context,
        String inviteToken,
        UUID nonce
    ) throws Exception {
        StoreInviteRequestDto request = storeInviteRequestDto(context, inviteToken, nonce);

        return mockMvc.perform(post(TestUri.INVITE_URI)
            .with(TestJwtBuilder.forDevice(context.user.getAuthId(), context.device.getDeviceType())
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("devices.invite")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions sync(
        DeviceContext context,
        MessageSyncRequestDto request
    ) throws Exception {
        return mockMvc.perform(post(TestUri.SYNC_URI)
            .with(TestJwtBuilder.forDevice(context.user.getAuthId(), context.device.getDeviceType())
                .buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)));
    }

    private StoreInviteRequestDto storeInviteRequestDto(
        DeviceContext context,
        String inviteToken,
        UUID nonce
    ) throws GeneralSecurityException {
        int keyVersion = 2;
        DeviceType inviteDeviceType = DeviceType.BROWSER;

        byte[] payload = new StoreInviteAuthRequest(
            null,
            nonce,
            context.device.getPublicId(),
            inviteToken,
            inviteDeviceType,
            keyVersion
        ).payload();

        return new StoreInviteRequestDto(
            context.device.getPublicId(),
            inviteToken,
            keyVersion,
            inviteDeviceType,
            nonce,
            sign(context.keyPair.getPrivate(), payload)
        );
    }

    private MessageSyncRequestDto messageSyncRequestDto(DeviceContext context, UUID nonce) throws GeneralSecurityException {
        long lastMessageId = 0L;
        int limit = 100;
        byte[] payload = new MessageSyncAuthRequest(
            null,
            nonce,
            context.device.getPublicId(),
            lastMessageId,
            limit
        ).payload();

        return new MessageSyncRequestDto(
            context.device.getPublicId(),
            lastMessageId,
            limit,
            nonce,
            sign(context.keyPair.getPrivate(), payload)
        );
    }

    private ResultActions registerWithInvalidPublicKey(
        UUID authId,
        UUID nonce
    ) throws Exception {
        DeviceRegisterRequestDto request = new DeviceRegisterRequestDto(
            "test name",
            "a".repeat(44),
            Map.of("platform", "android"),
            null,
            nonce,
            "a".repeat(80)
        );

        return mockMvc.perform(post(TestUri.REGISTER_URI)
            .with(TestJwtBuilder.forDevice(authId, DeviceType.MOBILE).buildMockMvcJwt()
                .authorities(new SimpleGrantedAuthority("messages.read")))
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)));
    }

    private DeviceContext saveUserWithDevice() throws GeneralSecurityException {
        KeyPair keyPair = TestCrypto.generateKeyPair();

        User user = new User();
        user.setAuthId(UUID.randomUUID());
        userRepository.saveAndFlush(user);

        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setUser(user);
        device.setDeviceType(DeviceType.MOBILE);
        device.setName("test name");
        device.setPublicKeyBytes(keyPair.getPublic().getEncoded());
        device.setKeyCreatedAt(Instant.now());
        device.setLastActiveAt(Instant.now());
        device.setExtras(Map.of("platform", "android"));
        deviceRepository.saveAndFlush(device);

        return new DeviceContext(user, device, keyPair);
    }

    private String sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(TestCrypto.sign(privateKey, payload));
    }

    private record DeviceContext(User user, Device device, KeyPair keyPair) {
    }

}
