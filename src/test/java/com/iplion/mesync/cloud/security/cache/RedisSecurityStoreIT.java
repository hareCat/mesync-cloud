package com.iplion.mesync.cloud.security.cache;

import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.RedisOperationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class RedisSecurityStoreIT extends BaseIT {
    @Autowired
    private RedisSecurityStore redisSecurityStore;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @AfterEach
    void cleanUp() {
        Assertions.assertNotNull(redisTemplate.getConnectionFactory());
        try (var connection = Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection()) {
            connection.serverCommands().flushDb();
        }
    }

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

    @Test
    void validateSecurityLimits_shouldReject() {
        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            0
        ))
            .isInstanceOfSatisfying(RedisOperationException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REDIS_OPERATION_FAILED)
            );

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ZERO,
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOfSatisfying(RedisOperationException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REDIS_OPERATION_FAILED)
            );

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(-1),
            3
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

}
