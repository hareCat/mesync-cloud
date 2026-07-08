package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.message.MessagePublishRequestDto;
import com.iplion.mesync.cloud.controller.dto.message.MessageSyncRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.MessageRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.request.MessagePublishAuthRequest;
import com.iplion.mesync.cloud.security.request.MessageSyncAuthRequest;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import com.iplion.mesync.cloud.testUtils.TestUri;
import org.hamcrest.Matchers;
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
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class MessagingControllerIT extends BaseIT {
    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    DeviceRepository deviceRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    MessageRepository messageRepository;

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
    void publish_shouldReturn201CreatedAndPublishNewMessage() throws Exception {
        TestContext context = TestDataFactory.createPublishContext(userRepository, deviceRepository);
        var requestDto = context.messagePublishRequestDto;

        mockMvc.perform(post(TestUri.PUBLISH_URI)
                .with(TestJwtBuilder.forDevice(context.user.getAuthId(), context.device.getDeviceType())
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.publish")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.messagePublicId").exists());

        List<Message> messages = messageRepository.findAll();
        assertThat(messages).hasSize(1);
        Message message = messages.get(0);

        assertThat(message.getPublicId()).isEqualTo(requestDto.messagePublicId());
        assertThat(message.getUser().getId()).isEqualTo(context.user.getId());
        assertThat(message.getDevice().getId()).isEqualTo(context.device.getId());
        assertThat(message.getAddress()).isEqualTo(requestDto.address());
        assertThat(message.getMessageType()).isEqualTo(requestDto.messageType());
        assertThat(message.getDirection()).isEqualTo(requestDto.direction());
        assertThat(message.getOccurredAt().truncatedTo(ChronoUnit.MILLIS))
            .isEqualTo(requestDto.occurredAt().truncatedTo(ChronoUnit.MILLIS));
        assertThat(message.getKeyVersion()).isEqualTo(requestDto.keyVersion());
        assertThat(message.getCiphertext()).isEqualTo(context.ciphertext);
    }

    @Test
    void publish_shouldReturn403_whenJwtUserDoesNotOwnRequestDevice() throws Exception {
        KeyPair deviceAKeyPair = TestCrypto.generateKeyPair();
        KeyPair deviceBKeyPair = TestCrypto.generateKeyPair();

        User userA = TestModelFactory.user();
        User userB = TestModelFactory.user();
        userRepository.saveAllAndFlush(List.of(userA, userB));

        Device deviceA = TestDataFactory.device(userA, "user A device", deviceAKeyPair.getPublic().getEncoded());
        Device deviceB = TestDataFactory.device(userB, "user B device", deviceBKeyPair.getPublic().getEncoded());
        deviceRepository.saveAllAndFlush(List.of(deviceA, deviceB));

        UUID messagePublicId = UUID.randomUUID();
        String address = "address";
        MessageType messageType = MessageType.SMS;
        MessageDirection direction = MessageDirection.INCOMING;
        Instant occurredAt = Instant.now();
        Integer keyVersion = 2;
        byte[] ciphertext = new byte[32];
        String base64Ciphertext = Base64.getEncoder().encodeToString(ciphertext);
        UUID nonce = UUID.randomUUID();

        byte[] payload = new MessagePublishAuthRequest(
            null,
            nonce,
            deviceB.getPublicId(),
            messagePublicId,
            address,
            messageType,
            direction,
            occurredAt,
            keyVersion,
            base64Ciphertext
        ).payload();

        String base64Signature = Base64.getEncoder().encodeToString(
            TestCrypto.sign(deviceBKeyPair.getPrivate(), payload)
        );

        var requestDto = new MessagePublishRequestDto(
            deviceB.getPublicId(),
            messagePublicId,
            address,
            messageType,
            direction,
            occurredAt,
            keyVersion,
            base64Ciphertext,
            nonce,
            base64Signature
        );

        mockMvc.perform(post(TestUri.PUBLISH_URI)
                .with(TestJwtBuilder.forDevice(userA.getAuthId(), deviceA.getDeviceType())
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.publish")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isForbidden());

        assertThat(messageRepository.findAll()).isEmpty();
    }

    @Test
    void sync_shouldReturn200AndMessageDtos() throws Exception {
        TestContext context = TestDataFactory.createSyncContext(userRepository, deviceRepository);
        var requestDto = context.messageSyncRequestDto;

        Device anotherDevice = TestDataFactory.device(
            context.user,
            "another name",
            TestCrypto.generateKeyPair().getPublic().getEncoded()
        );
        deviceRepository.saveAndFlush(anotherDevice);

        Message first = TestModelFactory.message(context.user, anotherDevice);
        Message second = TestModelFactory.message(context.user, null);
        messageRepository.saveAll(List.of(first, second));

        mockMvc.perform(post(TestUri.SYNC_URI)
                .with(TestJwtBuilder.forDevice(context.user.getAuthId(), context.device.getDeviceType())
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.messages").isArray())
            .andExpect(jsonPath("$.messages.length()").value(2))
            .andExpect(jsonPath("$.messages[0].messagePublicId").value(first.getPublicId().toString()))
            .andExpect(jsonPath("$.messages[0].devicePublicId").value(anotherDevice.getPublicId().toString()))
            .andExpect(jsonPath("$.messages[1].messagePublicId").value(second.getPublicId().toString()))
            .andExpect(jsonPath("$.messages[1].devicePublicId").value(Matchers.nullValue()));
    }

    // --------------------------- helpers ------------------------

    private static class TestContext {
        User user;
        Device device;
        UUID messageId;
        String address;
        MessageType messageType;
        MessageDirection messageDirection;
        Instant occurredAt;
        String base64Ciphertext;
        byte[] ciphertext;
        Long lastMessageId;
        Integer limit;
        UUID nonce;
        Integer keyVersion;
        String base64Signature;
        MessagePublishRequestDto messagePublishRequestDto;
        MessageSyncRequestDto messageSyncRequestDto;
    }

    private static class TestDataFactory {
        private static TestContext createContext(
            KeyPair keyPair,
            UserRepository userRepository,
            DeviceRepository deviceRepository
        ) {
            var context = new TestContext();

            User user = TestModelFactory.user();
            userRepository.saveAndFlush(user);
            context.user = user;

            Device device = device(user, "test name", keyPair.getPublic().getEncoded());
            deviceRepository.saveAndFlush(device);
            context.device = device;

            context.messageId = UUID.randomUUID();
            context.address = "address";
            context.messageType = MessageType.SMS;
            context.messageDirection = MessageDirection.INCOMING;
            context.occurredAt = Instant.now();
            context.ciphertext = new byte[32];
            context.base64Ciphertext = Base64.getEncoder().encodeToString(context.ciphertext);
            context.lastMessageId = 0L;
            context.limit = 100;
            context.nonce = UUID.randomUUID();
            context.keyVersion = 2;

            return context;
        }

        public static TestContext createPublishContext(
            UserRepository userRepository,
            DeviceRepository deviceRepository
        ) throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.createContext(keyPair, userRepository, deviceRepository);
            byte[] payload = new MessagePublishAuthRequest(
                null,
                context.nonce,
                context.device.getPublicId(),
                context.messageId,
                context.address,
                context.messageType,
                context.messageDirection,
                context.occurredAt,
                context.keyVersion,
                context.base64Ciphertext
            ).payload();

            context.base64Signature = Base64.getEncoder().encodeToString(
                TestCrypto.sign(keyPair.getPrivate(), payload)
            );

            context.messagePublishRequestDto = new MessagePublishRequestDto(
                context.device.getPublicId(),
                context.messageId,
                context.address,
                context.messageType,
                context.messageDirection,
                context.occurredAt,
                context.keyVersion,
                context.base64Ciphertext,
                context.nonce,
                context.base64Signature
            );

            return context;
        }

        public static TestContext createSyncContext(
            UserRepository userRepository,
            DeviceRepository deviceRepository
        ) throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.createContext(keyPair, userRepository, deviceRepository);
            byte[] payload = new MessageSyncAuthRequest(
                null,
                context.nonce,
                context.device.getPublicId(),
                context.lastMessageId,
                context.limit
            ).payload();
            context.base64Signature = Base64.getEncoder().encodeToString(
                TestCrypto.sign(keyPair.getPrivate(), payload)
            );

            context.messageSyncRequestDto = new MessageSyncRequestDto(
                context.device.getPublicId(),
                context.lastMessageId,
                context.limit,
                context.nonce,
                context.base64Signature
            );

            return context;
        }

        public static Device device(User user, String name, byte[] publicKeyBytes) {
            Device device = new Device();
            device.setUser(user);
            device.setDeviceType(DeviceType.MOBILE);
            device.setName(name);
            device.setPublicKeyBytes(publicKeyBytes);
            device.setKeyCreatedAt(Instant.now());
            device.setLastActiveAt(Instant.now());
            device.setExtras(Map.of("platform", "android"));

            return device;
        }

    }

}
