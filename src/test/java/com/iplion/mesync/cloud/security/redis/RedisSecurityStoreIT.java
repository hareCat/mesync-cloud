package com.iplion.mesync.cloud.security.redis;

import com.iplion.mesync.cloud.BaseIT;
import com.iplion.mesync.cloud.error.AuthException;
import com.iplion.mesync.cloud.error.RedisOperationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
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
        assertThatCode(() -> redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .doesNotThrowAnyException();
    }

    @Test
    public void registrationSecurityCheck_shouldPass() {
        assertThatCode(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .doesNotThrowAnyException();
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

        assertThatThrownBy(() -> redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining(nonceKey);
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

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            nonceKey,
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining(nonceKey);
    }

    @Test
    public void deviceAuthSecurityCheck_shouldRejectWithRevoked() {
        String revokedKey = "revokedKey";

        redisSecurityStore.set(
            revokedKey,
            true,
            Duration.ofMinutes(10)
        );

        assertThatThrownBy(() -> redisSecurityStore.deviceAuthSecurityCheck(
            revokedKey,
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining(revokedKey);
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

        assertThatThrownBy(() -> redisSecurityStore.deviceAuthSecurityCheck(
            "revokedKey",
            "nonceKey",
            rateLimitKey,
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining(rateLimitKey);
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

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            rateLimitKey,
            Duration.ofMinutes(1),
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining(rateLimitKey);
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
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("rate");

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ZERO,
            Duration.ofMinutes(1),
            3
        ))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("TTL", "nonce");

        assertThatThrownBy(() -> redisSecurityStore.registrationSecurityCheck(
            "nonceKey",
            "rateLimitKey",
            Duration.ofMinutes(1),
            Duration.ofMinutes(-1),
            3
        ))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("TTL", "rate");

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
