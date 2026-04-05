package com.iplion.mesync.cloud.infrastructure.redis;

import com.iplion.mesync.cloud.error.RedisOperationException;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

//TODO add redis nodes
@Service
@RequiredArgsConstructor
public final class RedisSecurityStore {
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisScript<Long> rateLimitScript;

    public <T> void set(String redisKey, T value, Duration ttl) {
        execute(() -> redisTemplate.opsForValue().set(redisKey, value, ttl));
    }

    public long increment(String redisKey) {
        return execute(() -> redisTemplate.opsForValue().increment(redisKey));
    }

    public boolean expire(String redisKey, Duration ttl) {
        return execute(() -> redisTemplate.expire(redisKey, ttl));
    }

    public long incrementWithTtl(String key, Duration ttl) {
        Long value = execute(() -> redisTemplate.execute(
            rateLimitScript,
            List.of(key),
            String.valueOf(ttl.getSeconds())
        ));

        if (value == null) {
            throw new RedisOperationException("Rate limit script returned \"null\"");
        }

        return value;
    }

    @Nullable
    public <T> T get(String key, Class<T> clazz) {
        return clazz.cast(
            execute(() -> redisTemplate.opsForValue().get(key))
        );
    }

    @Nullable
    public <T> T getAndDelete(String key, Class<T> clazz) {
        return clazz.cast(
            execute(() -> redisTemplate.opsForValue().getAndDelete(key))
        );
    }

    public boolean setIfAbsent(String key, String value, Duration ttl) {
        return execute(() -> Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(key, value, ttl)));
    }

    private <T> T execute(Supplier<T> supplier) {
        try {
            return supplier.get();
        } catch (DataAccessException e) {
            throw new RedisOperationException(e);
        }
    }

    private void execute(Runnable action) {
        try {
            action.run();
        } catch (DataAccessException e) {
            throw new RedisOperationException(e);
        }
    }
}
