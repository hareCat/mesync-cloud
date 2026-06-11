package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.auth.DeviceAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.testUtils.TestCrypto;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

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
public class AuthServiceTest {
    @Mock
    RedisSecurityStore redisSecurityStore;

    @Mock
    KeySignatureService keySignatureService;

    @Mock
    AuthContextService authContextService;

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
        null,
        null
    );
    AppProperties.Registration regProps = appProperties.registration();
    AppProperties.Auth authProps = appProperties.auth();

    AuthService authService;

    TestContext testContext;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        authService = new AuthService(
            redisSecurityStore,
            keySignatureService,
            authContextService,
            appProperties
        );

        testContext = createContext();

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(testContext.jwt));
    }

    @Test
    public void verifyRegistrationRequest_shouldReturnResult_whenRequestValid() {
        RegistrationAuthRequest request = new RegistrationAuthRequest(
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.base64PublicKey,
            UUID.randomUUID()
        );

        when(keySignatureService.createPublicKey(any())).thenReturn(testContext.publicKey);

        RegistrationAuthResult result = authService.verifyRegistrationRequest(request);

        verify(redisSecurityStore).registrationSecurityCheck(
            eq(RedisKeys.registrationNonceKey(testContext.userAuthId(), testContext.nonce())),
            eq(RedisKeys.registrationRateLimitKey(testContext.userAuthId())),
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
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1
        );

        when(authContextService.getAuthContext(any(), any())).thenReturn(testContext.authData);

        AuthData result = authService.verifyDeviceManagerRequest(request);

        verify(authContextService).getAuthContext(eq(testContext.userAuthId), eq(testContext.devicePublicId));
        verify(redisSecurityStore).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(request.devicePublicId())),
            eq(RedisKeys.authNonceKey(request.devicePublicId(), testContext.nonce())),
            eq(RedisKeys.authRateLimitKey(request.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );
        verify(keySignatureService).verify(eq(testContext.publicKey), eq(request.payload()), any(byte[].class));

        assertThat(result).isEqualTo(testContext.authData());
    }

    @Test
    public void verifyRegistrationRequest_shouldThrow_whenJwtInvalid() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(mock(Jwt.class)));

        var request = new RegistrationAuthRequest(
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.base64PublicKey(),
            UUID.randomUUID()
        );

        assertThatThrownBy(() -> authService.verifyRegistrationRequest(request))
            .isInstanceOf(AuthException.class)
            .hasCauseInstanceOf(InvalidTokenException.class);

        verify(redisSecurityStore, never()).registrationSecurityCheck(any(), any(), any(), any(), anyInt());
    }

    @Test
    void verifyDeviceManagerRequest_shouldThrow_whenOwnershipMismatch() {
        var request = new SaveInviteAuthRequest(
            testContext.base64Signature(),
            UUID.randomUUID(),
            testContext.devicePublicId(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1
        );

        AuthData fromContext = testContext.authData;
        AuthData wrongOwnerDevice = new AuthData(
            new UserAuthData(
                fromContext.userAuthData().id(),
                UUID.randomUUID(),
                1
            ),
            new DeviceAuthData(
                fromContext.deviceAuthData().id(),
                fromContext.deviceAuthData().publicId(),
                fromContext.deviceAuthData().deviceType(),
                fromContext.deviceAuthData().publicKey()
            )
        );

        when(authContextService.getAuthContext(any(), any())).thenReturn(wrongOwnerDevice);

        assertThatThrownBy(() -> authService.verifyDeviceManagerRequest(request))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("owner");

        verify(keySignatureService, never()).verify(any(), any(), any());
    }

    @Test
    void verifyMessagingRequest_shouldReturnDeviceAuthData_whenRequestValid() {
        var request = new TestDeviceAuthRequest(
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId()
        );

        when(authContextService.getAuthContext(any(), any())).thenReturn(testContext.authData);

        AuthData result = authService.verifyMessagingRequest(request);

        verify(authContextService).getAuthContext(eq(testContext.userAuthId), eq(testContext.devicePublicId));
        verify(redisSecurityStore).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(request.devicePublicId())),
            eq(RedisKeys.authNonceKey(request.devicePublicId(), testContext.nonce())),
            eq(RedisKeys.authRateLimitKey(request.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );
        verify(keySignatureService).verify(eq(testContext.publicKey), eq(request.payload()), any(byte[].class));

        assertThat(result).isEqualTo(testContext.authData());


    }

    @Test
    void verifyMessagingRequest_shouldThrow_whenRequestDeviceTypeMismatch() {
        var request = new TestDeviceAuthRequest(
            testContext.base64Signature(),
            testContext.nonce(),
            testContext.devicePublicId()
        );

        AuthData fromContext = testContext.authData;
        AuthData wrongtypeDevice = new AuthData(
            new UserAuthData(
                fromContext.userAuthData().id(),
                fromContext.userAuthData().authId(),
                fromContext.userAuthData().keyVersion()
            ),
            new DeviceAuthData(
                fromContext.deviceAuthData().id(),
                fromContext.deviceAuthData().publicId(),
                DeviceType.BROWSER,
                fromContext.deviceAuthData().publicKey()
            )
        );

        when(authContextService.getAuthContext(any(), any())).thenReturn(wrongtypeDevice);

        assertThatThrownBy(() -> authService.verifyMessagingRequest(request))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("type");

        verify(keySignatureService, never()).verify(any(), any(), any());
    }

    @Test
    void verifyRegistrationRequest_shouldUseRequestNonceInRedisNonceKey() {
        UUID firstNonce = UUID.randomUUID();
        UUID secondNonce = UUID.randomUUID();
        var firstRequest = new RegistrationAuthRequest(
            testContext.base64Signature(),
            firstNonce,
            testContext.base64PublicKey,
            UUID.randomUUID()
        );
        var secondRequest = new RegistrationAuthRequest(
            testContext.base64Signature(),
            secondNonce,
            testContext.base64PublicKey,
            UUID.randomUUID()
        );

        when(keySignatureService.createPublicKey(any())).thenReturn(testContext.publicKey);

        authService.verifyRegistrationRequest(firstRequest);
        authService.verifyRegistrationRequest(secondRequest);

        ArgumentCaptor<String> nonceKeyCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisSecurityStore, times(2)).registrationSecurityCheck(
            nonceKeyCaptor.capture(),
            eq(RedisKeys.registrationRateLimitKey(testContext.userAuthId())),
            eq(regProps.nonceTtl()),
            eq(regProps.rateLimitTtl()),
            eq(regProps.attempts())
        );

        assertThat(nonceKeyCaptor.getAllValues().get(0))
            .isEqualTo(RedisKeys.registrationNonceKey(testContext.userAuthId(), firstNonce));
        assertThat(nonceKeyCaptor.getAllValues().get(1))
            .isEqualTo(RedisKeys.registrationNonceKey(testContext.userAuthId(), secondNonce));
    }

    @Test
    void verifyMessagingRequest_shouldUseRequestNonceInRedisNonceKey() {
        UUID firstNonce = UUID.randomUUID();
        UUID secondNonce = UUID.randomUUID();
        var firstRequest = new TestDeviceAuthRequest(
            testContext.base64Signature(),
            firstNonce,
            testContext.devicePublicId()
        );
        var secondRequest = new TestDeviceAuthRequest(
            testContext.base64Signature(),
            secondNonce,
            testContext.devicePublicId()
        );

        when(authContextService.getAuthContext(any(), any())).thenReturn(testContext.authData);

        authService.verifyMessagingRequest(firstRequest);
        authService.verifyMessagingRequest(secondRequest);

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
        UUID userAuthId,
        String base64PublicKey,
        PublicKey publicKey,
        String base64Signature,
        UUID devicePublicId,
        UUID nonce,
        AuthData authData
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
        AuthData authData = new AuthData(
            new UserAuthData(
                1L,
                authId,
                1
            ),
            new DeviceAuthData(
                1L,
                devicePublicId,
                deviceType,
                keyPair.getPublic()
            )
        );

        return new TestContext(
            jwt,
            authId,
            base64PublicKey,
            keyPair.getPublic(),
            base64Signature,
            devicePublicId,
            UUID.randomUUID(),
            authData
        );
    }

    private record TestDeviceAuthRequest(
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
