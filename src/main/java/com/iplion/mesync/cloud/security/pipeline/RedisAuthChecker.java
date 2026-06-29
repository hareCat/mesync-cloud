package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.security.request.RegisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.request.UnregisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityCheckResult;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class RedisAuthChecker {
    private final RedisSecurityStore redisSecurityStore;
    private final AppProperties appProperties;

    void unregisteredDeviceSecurityCheck(AuthPipelineContext<? extends UnregisteredDeviceAuthRequest> context) {
        var registrationProperties = appProperties.registration();
        UUID authId = context.getJwtUserData().authId();
        UUID nonce = context.getRequest().nonce();

        RedisSecurityCheckResult result = redisSecurityStore.registrationSecurityCheck(
            RedisKeys.registrationNonceKey(authId, nonce),
            RedisKeys.registrationRateLimitKey(authId),
            registrationProperties.nonceTtl(),
            registrationProperties.rateLimitTtl(),
            registrationProperties.attempts()
        );

        handleRedisSecurityCheckResult(result);
    }

    void registeredDeviceSecurityCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        var authProperties = appProperties.auth();
        UUID devicePublicId = context.getRequest().devicePublicId();
        UUID nonce = context.getRequest().nonce();

        RedisSecurityCheckResult result = redisSecurityStore.deviceAuthSecurityCheck(
            RedisKeys.authDeviceRevokedKey(devicePublicId),
            RedisKeys.authNonceKey(devicePublicId, nonce),
            RedisKeys.authRateLimitKey(devicePublicId),
            authProperties.nonceTtl(),
            authProperties.rateLimitTtl(),
            authProperties.attempts()
        );

        handleRedisSecurityCheckResult(result);
    }

    private void handleRedisSecurityCheckResult(RedisSecurityCheckResult result) {
        switch (result) {
            case OK -> {}
            case REPLAY -> throw AuthException.replay();
            case RATE_LIMIT -> throw AuthException.rateLimit();
            case REVOKED -> throw AuthException.revoked();
        }
    }
}
