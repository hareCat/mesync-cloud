package com.iplion.mesync.cloud.security.cache;

import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.RedisOperationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class RedisSecurityStoreIT extends BaseIT {
    @Autowired
    private RedisSecurityStore redisSecurityStore;

    @Test
    public void deviceAuthSecurityCheck_shouldPass() {
        RedisSecurityCheckResult result = redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.OK);
    }

    @Test
    public void registrationSecurityCheck_shouldPass() {
        RedisSecurityCheckResult result = redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.OK);
    }

    @Test
    public void deviceAuthSecurityCheck_shouldRejectWithNonceReplay() {
        String nonceKey = "nonceKey";

        redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        RedisSecurityCheckResult result = redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.REPLAY);
    }

    @Test
    public void registrationSecurityCheck_shouldRejectWithNonceReplay() {
        String nonceKey = "nonceKey";

        redisSecurityStore.registrationSecurityCheck(
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        RedisSecurityCheckResult result = redisSecurityStore.registrationSecurityCheck(
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.REPLAY);
    }

    @Test
    public void deviceAuthSecurityCheck_shouldRejectWithRevoked() {
        String revokedKey = "revokedKey";

        redisSecurityStore.set(
            revokedKey,
            true,
            Duration.ofMinutes(10)
        );

        RedisSecurityCheckResult result = redisSecurityStore.deviceAuthSecurityCheck(
            revokedKey,
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.REVOKED);
    }

    @Test
    public void deviceAuthSecurityCheck_shouldRejectWithRateLimit() {
        String rateLimitKey = "rateLimitKey";

        for (int i = 0; i < 3; i++) {
            redisSecurityStore.deviceAuthSecurityCheck(
                "revokedKey",
                "nonceKey" + i,
                rateLimitKey,
                Duration.ofMinutes(1),
                Duration.ofMinutes(1),
                3
            );
        }

        RedisSecurityCheckResult result = redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            "nonceKey",
            rateLimitKey,
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.RATE_LIMIT);
    }

    @Test
    public void registrationSecurityCheck_shouldRejectWithRateLimit() {
        String rateLimitKey = "rateLimitKey";

        for (int i = 0; i < 3; i++) {
            redisSecurityStore.registrationSecurityCheck(
                "nonceKey" + i,
                rateLimitKey,
                Duration.ofMinutes(1),
                Duration.ofMinutes(1),
                3
            );
        }

        RedisSecurityCheckResult result = redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            rateLimitKey,
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        );

        assertThat(result).isEqualTo(RedisSecurityCheckResult.RATE_LIMIT);
    }

    @ParameterizedTest
    @MethodSource("invalidSecurityLimits")
    void validateSecurityLimits_shouldReject(
        Duration nonceTtl,
        Duration rateLimitTtl,
        int rateLimit
    ) {
        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            nonceTtl,
            rateLimitTtl,
            rateLimit
        ))
            .isInstanceOfSatisfying(RedisOperationException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REDIS_OPERATION_FAILED)
            );
    }

    @Test
    @SuppressWarnings("unchecked")
    void setAndGet_shouldWork() {
        Map<String, Object> dto = Map.of("abc", 555);

        redisSecurityStore.set(
            "key",
            dto,
            Duration.ofMinutes(1)
        );

        Map<String, Object> beforeDelete = redisSecurityStore.getAndDelete("key", Map.class);
        Map<String, Object> afterDelete = redisSecurityStore.getAndDelete("key", Map.class);

        assertThat(beforeDelete).isEqualTo(dto);
        assertThat(afterDelete).isNull();
    }

    private static Stream<Arguments> invalidSecurityLimits() {
        return Stream.of(
            Arguments.of(Duration.ofMinutes(1), Duration.ofMinutes(1), 0),
            Arguments.of(Duration.ZERO, Duration.ofMinutes(1), 3),
            Arguments.of(Duration.ofMinutes(1), Duration.ofMinutes(-1), 3)
        );
    }

}
