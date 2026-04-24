package com.iplion.mesync.cloud.infrastructure.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.error.RedisOperationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RedisSecurityStoreTest {
    @Mock
    private RedisTemplate<String, Object> redisTemplate;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    RedisSecurityStore redisSecurityStore;

    @Test
    public void incrementWithTtl_whenInvalidTtl_shouldThrowRedisOperationException() {
        assertThatThrownBy(() -> redisSecurityStore.incrementWithTtl("key", Duration.ofSeconds(0)))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("TTL");

        assertThatThrownBy(() -> redisSecurityStore.incrementWithTtl("key", Duration.ofSeconds(-1)))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("TTL");
    }

    @Test
    public void incrementWithTtl_whenRedisNotAvailable_shouldThrowRedisOperationExceptionWithCauseDataAccessException() {
        when(redisTemplate.execute(any(), any(), any())).thenThrow(new DataAccessException("error") {});

        assertThatThrownBy(() -> redisSecurityStore.incrementWithTtl("key", Duration.ofSeconds(5)))
            .isInstanceOf(RedisOperationException.class)
            .hasCauseInstanceOf(DataAccessException.class);
    }

    @Test
    public void incrementWithTtl_whenRedisSavingError_shouldThrowRedisOperationException() {
        when(redisTemplate.execute(any(), any(), any())).thenReturn(null);

        assertThatThrownBy(() -> redisSecurityStore.incrementWithTtl("key", Duration.ofSeconds(5)))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("null");
    }

    @Test
    public void incrementWithTtl_shouldReturnTtl() {
        Duration ttl = Duration.ofSeconds(5);

        when(redisTemplate.execute(any(), any(), any())).thenReturn(ttl.toSeconds());

        assertThat(redisSecurityStore.incrementWithTtl("key", ttl))
            .isEqualTo(ttl.toSeconds());

        verify(redisTemplate).execute(any(), eq(List.of("key")), eq(5L));
    }

    @Test
    public void getAndDelete_whenConvertFails_shouldThrownRedisOperationException() {
        Integer someIntValue = 5;

        var valueOps = mockValueOps();

        when(valueOps.getAndDelete(any())).thenReturn(someIntValue);
        when(objectMapper.convertValue(any(), eq(Integer.class)))
            .thenThrow(new IllegalArgumentException());

        assertThatThrownBy(() -> redisSecurityStore.getAndDelete("key", Integer.class))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("convert");
    }

    @Test
    public void get_whenRedisReturnNull_shouldReturnNull() {
        var valueOps = mockValueOps();

        when(valueOps.get(any())).thenReturn(null);

        assertThat(redisSecurityStore.get("key", Integer.class)).isNull();
    }

    @Test
    void get_whenRedisFails_shouldThrowRedisOperationException() {
        var valueOps = mockValueOps();

        when(valueOps.get(any())).thenThrow(new DataAccessException("err") {});

        assertThatThrownBy(() -> redisSecurityStore.get("key", Integer.class))
            .isInstanceOf(RedisOperationException.class)
            .hasCauseInstanceOf(DataAccessException.class);
    }

    @Test
    void setIfAbsent_shouldHandleNullFalseTrue() {
        var valueOps = mockValueOps();

        when(valueOps.setIfAbsent(any(), any(), any()))
            .thenReturn(null)
            .thenReturn(true)
            .thenReturn(false);

        assertThat(redisSecurityStore.setIfAbsent("key", "value", Duration.ofSeconds(30))).isFalse();
        assertThat(redisSecurityStore.setIfAbsent("key", "value", Duration.ofSeconds(30))).isTrue();
        assertThat(redisSecurityStore.setIfAbsent("key", "value", Duration.ofSeconds(30))).isFalse();

        verify(valueOps, times(3)).setIfAbsent(any(), any(), any());
    }

    @Test
    void setIfAbsent_whenRedisFails_shouldThrowRedisOperationException() {
        var valueOps = mockValueOps();

        when(valueOps.setIfAbsent(any(), any(), any()))
            .thenThrow(new DataAccessException("err") {});

        assertThatThrownBy(() ->
            redisSecurityStore.setIfAbsent("key", "value", Duration.ofSeconds(1))
        ).isInstanceOf(RedisOperationException.class);
    }

    @Test
    void set_whenRedisFails_shouldThrowRedisOperationException() {
        var valueOps = mockValueOps();

        doThrow(new DataAccessException("error") {}).when(valueOps).set(any(), any(), any());

        assertThatThrownBy(() -> redisSecurityStore.set("key", 666, Duration.ofSeconds(30)))
            .isInstanceOf(RedisOperationException.class)
            .hasCauseInstanceOf(DataAccessException.class);
    }

    private ValueOperations<String, Object> mockValueOps() {
        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        return valueOps;
    }

}
