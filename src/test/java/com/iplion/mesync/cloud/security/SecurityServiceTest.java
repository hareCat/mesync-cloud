package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.auth.DeviceAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.redis.RedisKeys;
import com.iplion.mesync.cloud.security.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.service.DeviceService;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SecurityServiceTest {
    @Mock
    RedisSecurityStore redisSecurityStore;

    @Mock
    KeySignatureService keySignatureService;

    @Mock
    DeviceService deviceService;

    AppProperties appProperties = new AppProperties(
        new AppProperties.Registration(
            Duration.ofMinutes(10),
            Duration.ofSeconds(60),
            Duration.ofSeconds(30),
            Duration.ofMinutes(10),
            10
        ),
        new AppProperties.Auth(
            Duration.ofSeconds(30),
            Duration.ofSeconds(60),
            120
        ),
        null
    );
    AppProperties.Registration regProps = appProperties.registration();
    AppProperties.Auth authProps = appProperties.auth();

    SecurityService securityService;

    TestContext testContext;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        securityService = new SecurityService(
            redisSecurityStore,
            keySignatureService,
            deviceService,
            appProperties
        );

        testContext = createContext();
    }

    @Test
    public void verifyRegistrationRequest_shouldReturnResult_whenRequestValid() {
        RegistrationAuthRequest request = new RegistrationAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.base64PublicKey,
            UUID.randomUUID()
        );

        when(keySignatureService.createPublicKey(any())).thenReturn(testContext.publicKey);

        RegistrationAuthResult result = securityService.verifyRegistrationRequest(request);

        verify(redisSecurityStore).registrationSecurityCheck(
            eq(RedisKeys.registrationNonceKey(testContext.authId(), testContext.nonce())),
            eq(RedisKeys.registrationRateLimitKey(testContext.authId())),
            eq(regProps.nonceTtl()),
            eq(regProps.rateLimitTtl()),
            eq(regProps.attempts())
        );
        verify(keySignatureService).verify(eq(testContext.publicKey), eq(request.payload()), any(byte[].class));

        assertThat(result.jwtUserData()).isNotNull();
        assertThat(result.publicKey()).isEqualTo(testContext.publicKey());

    }

    @Test
    public void verifyDeviceManagerRequest_shouldReturnResult_whenRequestValid() {
        var request = new SaveInviteAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1
        );

        when(deviceService.getDeviceAuthData(any())).thenReturn(testContext.deviceAuthData);

        DeviceAuthData result = securityService.verifyDeviceManagerRequest(request);

        verify(deviceService).getDeviceAuthData(eq(testContext.devicePublicId));
        verify(redisSecurityStore).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(request.devicePublicId())),
            eq(RedisKeys.authNonceKey(request.devicePublicId(), testContext.nonce())),
            eq(RedisKeys.authRateLimitKey(request.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );
        verify(keySignatureService).verify(eq(testContext.publicKey), eq(request.payload()), any(byte[].class));

        assertThat(result).isEqualTo(testContext.deviceAuthData());
    }

    @Test
    public void verifyRegistrationRequest_shouldThrow_whenJwtInvalid() {
        Jwt brokenJwt = mock(Jwt.class);

        var request = new RegistrationAuthRequest(
            brokenJwt,
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.base64PublicKey(),
            UUID.randomUUID()
        );

        assertThatThrownBy(() -> securityService.verifyRegistrationRequest(request))
            .isInstanceOf(AuthException.class)
            .hasCauseInstanceOf(InvalidTokenException.class);

        verify(redisSecurityStore, never()).registrationSecurityCheck(any(), any(), any(), any(), anyInt());
    }

    @Test
    void verifyDeviceManagerRequest_shouldThrow_whenOwnershipMismatch() {
        var request = new SaveInviteAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            UUID.randomUUID(),
            testContext.devicePublicId(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1
        );

        DeviceAuthData fromContext = testContext.deviceAuthData;
        DeviceAuthData wrongOwnerDevice = new DeviceAuthData(
            fromContext.deviceId(),
            fromContext.devicePublicId(),
            fromContext.userId(),
            UUID.randomUUID(),
            fromContext.deviceType(),
            fromContext.publicKey(),
            1
        );

        when(deviceService.getDeviceAuthData(any())).thenReturn(wrongOwnerDevice);

        assertThatThrownBy(() -> securityService.verifyDeviceManagerRequest(request))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("owner");

        verify(keySignatureService, never()).verify(any(), any(), any());
    }

    @Test
    void verifyMessagingRequest_shouldReturnDeviceAuthData_whenRequestValid() {
        var request = new TestDeviceAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId()
        );

        when(deviceService.getDeviceAuthData(any())).thenReturn(testContext.deviceAuthData);

        DeviceAuthData result = securityService.verifyMessagingRequest(request);

        verify(deviceService).getDeviceAuthData(eq(testContext.devicePublicId));
        verify(redisSecurityStore).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(request.devicePublicId())),
            eq(RedisKeys.authNonceKey(request.devicePublicId(), testContext.nonce())),
            eq(RedisKeys.authRateLimitKey(request.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );
        verify(keySignatureService).verify(eq(testContext.publicKey), eq(request.payload()), any(byte[].class));

        assertThat(result).isEqualTo(testContext.deviceAuthData());


    }

    @Test
    void verifyMessagingRequest_shouldThrow_whenRequestDeviceTypeMismatch() {
        var request = new TestDeviceAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId()
        );

        DeviceAuthData fromContext = testContext.deviceAuthData;
        DeviceAuthData wrongtypeDevice = new DeviceAuthData(
            fromContext.deviceId(),
            fromContext.devicePublicId(),
            fromContext.userId(),
            fromContext.userAuthId(),
            DeviceType.BROWSER,
            fromContext.publicKey(),
            1
        );

        when(deviceService.getDeviceAuthData(any())).thenReturn(wrongtypeDevice);

        assertThatThrownBy(() -> securityService.verifyMessagingRequest(request))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("type");

        verify(keySignatureService, never()).verify(any(), any(), any());
    }

    @Test
    void verifyRegistrationRequest_shouldUseRequestNonceInRedisNonceKey() {
        UUID firstNonce = UUID.randomUUID();
        UUID secondNonce = UUID.randomUUID();
        var firstRequest = new RegistrationAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            firstNonce,
            testContext.base64PublicKey,
            UUID.randomUUID()
        );
        var secondRequest = new RegistrationAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            secondNonce,
            testContext.base64PublicKey,
            UUID.randomUUID()
        );

        when(keySignatureService.createPublicKey(any())).thenReturn(testContext.publicKey);

        securityService.verifyRegistrationRequest(firstRequest);
        securityService.verifyRegistrationRequest(secondRequest);

        ArgumentCaptor<String> nonceKeyCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisSecurityStore, times(2)).registrationSecurityCheck(
            nonceKeyCaptor.capture(),
            eq(RedisKeys.registrationRateLimitKey(testContext.authId())),
            eq(regProps.nonceTtl()),
            eq(regProps.rateLimitTtl()),
            eq(regProps.attempts())
        );

        assertThat(nonceKeyCaptor.getAllValues().get(0))
            .isEqualTo(RedisKeys.registrationNonceKey(testContext.authId(), firstNonce));
        assertThat(nonceKeyCaptor.getAllValues().get(1))
            .isEqualTo(RedisKeys.registrationNonceKey(testContext.authId(), secondNonce));
    }

    @Test
    void verifyMessagingRequest_shouldUseRequestNonceInRedisNonceKey() {
        UUID firstNonce = UUID.randomUUID();
        UUID secondNonce = UUID.randomUUID();
        var firstRequest = new TestDeviceAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            firstNonce,
            testContext.devicePublicId()
        );
        var secondRequest = new TestDeviceAuthRequest(
            testContext.jwt(),
            testContext.base64Signature(),
            secondNonce,
            testContext.devicePublicId()
        );

        when(deviceService.getDeviceAuthData(any())).thenReturn(testContext.deviceAuthData);

        securityService.verifyMessagingRequest(firstRequest);
        securityService.verifyMessagingRequest(secondRequest);

        ArgumentCaptor<String> nonceKeyCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisSecurityStore, times(2)).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(testContext.devicePublicId())),
            nonceKeyCaptor.capture(),
            eq(RedisKeys.authRateLimitKey(testContext.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );

        assertThat(nonceKeyCaptor.getAllValues().get(0))
            .isEqualTo(RedisKeys.authNonceKey(testContext.devicePublicId(), firstNonce));
        assertThat(nonceKeyCaptor.getAllValues().get(1))
            .isEqualTo(RedisKeys.authNonceKey(testContext.devicePublicId(), secondNonce));
    }

    // test-context

    private record TestContext(
        Jwt jwt,
        UUID authId,
        String base64PublicKey,
        PublicKey publicKey,
        String base64Signature,
        UUID devicePublicId,
        UUID nonce,
        DeviceAuthData deviceAuthData
    ) {
    }

    private TestContext createContext() throws NoSuchAlgorithmException {
        UUID authId = UUID.randomUUID();
        UUID devicePublicId = UUID.randomUUID();
        DeviceType deviceType = DeviceType.MOBILE;

        Jwt jwt = TestJwtBuilder
            .forDevice(authId, deviceType)
            .buildJwt();

        KeyPair keyPair = TestCrypto.generateKeyPair();
        String base64PublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String base64Signature = Base64.getEncoder().encodeToString(new byte[64]);
        DeviceAuthData deviceAuthData = new DeviceAuthData(
            1L,
            devicePublicId,
            1L,
            authId,
            deviceType,
            keyPair.getPublic(),
            1
        );

        return new TestContext(
            jwt,
            authId,
            base64PublicKey,
            keyPair.getPublic(),
            base64Signature,
            devicePublicId,
            UUID.randomUUID(),
            deviceAuthData
        );
    }

    private record TestDeviceAuthRequest(
        Jwt jwt,
        String base64Signature,
        UUID nonce,
        UUID devicePublicId
    ) implements DeviceAuthRequest {

        @Override
        public byte[] payload() {
            return "test-payload".getBytes(StandardCharsets.UTF_8);
        }
    }

}
