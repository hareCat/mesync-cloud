package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.request.common.UnregisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

final class TestPipelineFactory {
    private TestPipelineFactory() {}

    static TestContext testContext() throws NoSuchAlgorithmException {
        UUID authId = UUID.randomUUID();
        UUID devicePublicId = UUID.randomUUID();
        UUID nonce = UUID.randomUUID();
        DeviceType deviceType = DeviceType.MOBILE;
        KeyPair keyPair = TestCrypto.generateKeyPair();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        byte[] signature = new byte[64];

        AuthData authData = createAuthData(
            authId,
            devicePublicId,
            deviceType,
            keyPair.getPublic()
        );

        return new TestContext(
            TestJwtBuilder.forDevice(authId, deviceType).buildJwt(),
            jwtUserData(authId, deviceType),
            authId,
            devicePublicId,
            nonce,
            publicKeyBytes,
            base64PublicKey,
            keyPair.getPublic(),
            Base64.getEncoder().encodeToString(signature),
            signature,
            authData
        );
    }

    private static JwtUserData jwtUserData(UUID authId, DeviceType deviceType) {
        return new JwtUserData(
            authId,
            deviceType.getClientId(),
            null,
            false
        );
    }

    private static AuthData createAuthData(
        UUID ownerAuthId,
        UUID devicePublicId,
        DeviceType deviceType,
        PublicKey publicKey
    ) {
        return new AuthData(
            new UserAuthData(
                1L,
                ownerAuthId,
                1
            ),
            new DeviceAuthData(
                1L,
                devicePublicId,
                ownerAuthId,
                deviceType,
                publicKey
            )
        );
    }

    static AuthPipelineContext<RegisteredDeviceAuthRequest> registeredAuthPipelineContext(TestContext testContext) {
        return new AuthPipelineContext<>(registeredDeviceAuthRequest(testContext));
    }

    static AuthPipelineContext<UnregisteredDeviceAuthRequest> unregisteredAuthPipelineContext(TestContext testContext) {
        return new AuthPipelineContext<>(unregisteredDeviceAuthRequest(testContext));
    }

    static RegisteredDeviceAuthRequest registeredDeviceAuthRequest(TestContext testContext) {
        return new TestRegisteredDeviceAuthRequest(
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId(),
            "test-payload".getBytes(StandardCharsets.UTF_8)
        );
    }

    static UnregisteredDeviceAuthRequest unregisteredDeviceAuthRequest(TestContext testContext) {
        return new TestUnregisteredDeviceAuthRequest(
            "test-signature",
            testContext.nonce(),
            testContext.base64PublicKey()
        );
    }

    record TestContext(
        Jwt jwt,
        JwtUserData jwtUserData,
        UUID userAuthId,
        UUID devicePublicId,
        UUID nonce,
        byte[] publicKeyBytes,
        String base64PublicKey,
        PublicKey publicKey,
        String base64Signature,
        byte[] signature,
        AuthData authData
    ) {
    }

    record TestRegisteredDeviceAuthRequest(
        String base64Signature,
        UUID nonce,
        UUID devicePublicId,
        byte[] payload
    ) implements RegisteredDeviceAuthRequest {
    }

    record TestUnregisteredDeviceAuthRequest(
        String base64Signature,
        UUID nonce,
        String base64SigningPublicKey
    ) implements UnregisteredDeviceAuthRequest {
        @Override
        public byte[] payload() {
            return "test-payload".getBytes(StandardCharsets.UTF_8);
        }
    }
}
