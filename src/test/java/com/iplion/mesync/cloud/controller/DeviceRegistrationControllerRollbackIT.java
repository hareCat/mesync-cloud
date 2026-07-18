package com.iplion.mesync.cloud.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.request.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.service.support.InvitationService;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import com.iplion.mesync.cloud.testUtils.TestUri;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class DeviceRegistrationControllerRollbackIT extends BaseIT {
    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoSpyBean
    InvitationService invitationService;

    @Autowired
    RedisSecurityStore redisSecurityStore;

    @Autowired
    DeviceRepository deviceRepository;

    @Autowired
    UserRepository userRepository;

    @Test
    void register_shouldRollbackDeviceSave_whenInviteDeleteFails() throws Exception {
        KeyPair newDeviceKeyPair = TestCrypto.generateKeyPair();

        var context = TestDataFactory.createRegistrationContext(newDeviceKeyPair);

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
        doReturn(false).when(invitationService).deleteDeviceInviteData(
            eq(context.authId),
            any(String.class)
        );

        mockMvc.perform(post(TestUri.REGISTER_URI)
                .with(TestJwtBuilder.forDevice(context.authId, context.deviceType).buildMockMvcJwt()
                    .authorities(new SimpleGrantedAuthority("messages.read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)))
            .andExpect(status().isInternalServerError());

        List<Device> devices = deviceRepository.findActiveByUserAuthId(context.authId);
        assertThat(devices).hasSize(1);
        assertThat(devices)
            .extracting(Device::getName)
            .containsExactly(context.deviceName);

        DeviceInviteData inviteData = redisSecurityStore.get(
            RedisKeys.registrationInviteKey(context.authId, context.inviteToken),
            DeviceInviteData.class
        );
        assertThat(inviteData).isNotNull();
    }

    private static class TestDataFactory {
        static class TestContext {
            UUID authId;
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

        static TestContext createRegistrationContext(KeyPair keyPair) throws GeneralSecurityException {
            TestContext context = prepareContext(keyPair);
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

        static void saveNewUserWithDevice(
            TestContext context,
            UUID devicePublicId,
            byte[] publicKeyBytes,
            DeviceRepository deviceRepository,
            UserRepository userRepository
        ) {
            User user = TestModelFactory.saveUser(context.authId, userRepository);
            TestModelFactory.saveDevice(
                devicePublicId,
                user,
                context.deviceType,
                context.deviceName,
                publicKeyBytes,
                context.extras,
                deviceRepository
            );
        }

        static DeviceRegisterRequestDto deviceRegisterRequestDto(TestContext context, KeyPair keyPair) {
            return new DeviceRegisterRequestDto(
                context.deviceName,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                context.extras,
                context.inviteToken,
                context.nonce,
                context.base64Signature
            );
        }

        private static TestContext prepareContext(KeyPair keyPair) {
            var context = new TestContext();
            context.authId = UUID.randomUUID();
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

        private static String sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
            return Base64.getEncoder().encodeToString(
                TestCrypto.sign(privateKey, payload)
            );
        }
    }
}
