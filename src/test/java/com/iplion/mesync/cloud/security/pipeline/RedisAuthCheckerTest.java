package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityCheckResult;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.security.request.common.UnregisteredDeviceAuthRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.time.Duration;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisAuthCheckerTest extends BaseUnitTest {
    @Mock
    RedisSecurityStore redisSecurityStore;

    AppProperties appProperties = appProperties();
    AppProperties.Registration regProps = appProperties.registration();
    AppProperties.Auth authProps = appProperties.auth();

    RedisAuthChecker redisAuthChecker;

    @BeforeEach
    void setUp() {
        redisAuthChecker = new RedisAuthChecker(redisSecurityStore, appProperties);
    }

    @Test
    void unregisteredDeviceSecurityCheck_shouldUseJwtAuthIdAndRequestNonce() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = unregisteredAuthPipelineContextWithJwtData(testContext);

        when(redisSecurityStore.registrationSecurityCheck(any(), any(), any(), any(), anyInt()))
            .thenReturn(RedisSecurityCheckResult.OK);

        redisAuthChecker.unregisteredDeviceSecurityCheck(authPipelineContext);

        verify(redisSecurityStore).registrationSecurityCheck(
            eq(RedisKeys.registrationNonceKey(testContext.userAuthId(), testContext.nonce())),
            eq(RedisKeys.registrationRateLimitKey(testContext.userAuthId())),
            eq(regProps.nonceTtl()),
            eq(regProps.rateLimitTtl()),
            eq(regProps.attempts())
        );
    }

    @Test
    void registeredDeviceSecurityCheck_shouldUseDevicePublicIdAndRequestNonce() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);

        when(redisSecurityStore.deviceAuthSecurityCheck(any(), any(), any(), any(), any(), anyInt()))
            .thenReturn(RedisSecurityCheckResult.OK);

        redisAuthChecker.registeredDeviceSecurityCheck(authPipelineContext);

        verify(redisSecurityStore).deviceAuthSecurityCheck(
            eq(RedisKeys.authDeviceRevokedKey(testContext.devicePublicId())),
            eq(RedisKeys.authNonceKey(testContext.devicePublicId(), testContext.nonce())),
            eq(RedisKeys.authRateLimitKey(testContext.devicePublicId())),
            eq(authProps.nonceTtl()),
            eq(authProps.rateLimitTtl()),
            eq(authProps.attempts())
        );
    }

    @Test
    void registeredDeviceSecurityCheck_shouldThrowRevoked_whenRedisReturnsRevoked() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);

        when(redisSecurityStore.deviceAuthSecurityCheck(any(), any(), any(), any(), any(), anyInt()))
            .thenReturn(RedisSecurityCheckResult.REVOKED);

        assertThatThrownBy(() -> redisAuthChecker.registeredDeviceSecurityCheck(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e -> {
                assertThat(e.getMessage()).contains("Device revoked");
                assertThat(e.getClientMessage()).isEqualTo("Unable to verify your device.");
            });
    }

    private AuthPipelineContext<UnregisteredDeviceAuthRequest> unregisteredAuthPipelineContextWithJwtData(
        TestPipelineFactory.TestContext testContext
    ) {
        var authPipelineContext = TestPipelineFactory.unregisteredAuthPipelineContext(testContext);
        authPipelineContext.setJwtUserData(testContext.jwtUserData());
        return authPipelineContext;
    }

    private AppProperties appProperties() {
        return new AppProperties(
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
    }

}
