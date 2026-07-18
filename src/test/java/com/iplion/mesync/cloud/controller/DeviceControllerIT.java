package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.device.DeviceListRequestDto;
import com.iplion.mesync.cloud.controller.dto.device.DeviceRevokeRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.request.DeviceListAuthRequest;
import com.iplion.mesync.cloud.security.request.DeviceRevokeAuthRequest;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import com.iplion.mesync.cloud.testUtils.TestUri;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
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
    private Cache<UUID, DeviceAuthData> deviceAuthCache;

    @Autowired
    private Cache<UUID, UserAuthData> userAuthCache;

    @Test
    void list_shouldReturnOtherUserDevices() throws Exception {
        var context = TestDataFactory.createDeviceListContext();

        User user = TestModelFactory.saveUser(
            context.authId,
            userRepository
        );
        Device currentDevice = TestModelFactory.saveMobileDevice(
            context.devicePublicId,
            user,
            context.deviceName,
            context.publicKeyBytes,
            context.extras,
            deviceRepository
        );
        Device otherDevice = TestModelFactory.saveMobileDevice(
            UUID.randomUUID(),
            user,
            "other " + context.deviceName,
            TestCrypto.generateKeyPair().getPublic().getEncoded(),
            context.extras,
            deviceRepository
        );
        Device revokedDevice = TestModelFactory.saveMobileDevice(
            UUID.randomUUID(),
            user,
            "revoked " + context.deviceName,
            TestCrypto.generateKeyPair().getPublic().getEncoded(),
            context.extras,
            deviceRepository
        );
        revokedDevice.setRevokedAt(Instant.now());
        deviceRepository.saveAndFlush(revokedDevice);

        var requestDto = TestDataFactory.deviceListRequestDto(context);

        mockMvc.perform(post(TestUri.DEVICE_LIST_URI)
                .with(TestJwtBuilder.forDevice(context.authId, currentDevice.getDeviceType())
                    .buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.devices.length()").value(2))
            .andExpect(jsonPath("$.devices[*].devicePublicId").value(containsInAnyOrder(
                otherDevice.getPublicId().toString(),
                revokedDevice.getPublicId().toString()
            )))
            .andExpect(jsonPath("$.devices[*].name").value(containsInAnyOrder(
                otherDevice.getName(),
                revokedDevice.getName()
            )));
    }

    @Test
    void revoke_shouldRevokeDeviceAndInvalidateDeviceAuthCache() throws Exception {
        UUID targetDevicePublicId = UUID.randomUUID();
        var context = TestDataFactory.createRevocationContext(targetDevicePublicId);
        var requestDto = TestDataFactory.deviceRevokeRequestDto(context, targetDevicePublicId);
        PublicKey targetDevicePublicKey = TestCrypto.generateKeyPair().getPublic();

        User user = TestModelFactory.saveUser(
            context.authId,
            userRepository
        );
        Device trustedDevice = TestModelFactory.saveMobileDevice(
            context.devicePublicId,
            user,
            context.deviceName,
            context.publicKeyBytes,
            context.extras,
            deviceRepository
        );
        Device targetDevice = TestModelFactory.saveMobileDevice(
            targetDevicePublicId,
            user,
            "target " + context.deviceName,
            targetDevicePublicKey.getEncoded(),
            context.extras,
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

        public static TestContext createDeviceListContext() throws GeneralSecurityException {
            KeyPair keyPair = TestCrypto.generateKeyPair();
            TestContext context = TestDataFactory.prepareContext(keyPair);
            byte[] payload = new DeviceListAuthRequest(
                null,
                context.nonce,
                context.devicePublicId
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

        public static DeviceListRequestDto deviceListRequestDto(TestContext context) {
            return new DeviceListRequestDto(
                context.devicePublicId,
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
