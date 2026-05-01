package com.iplion.mesync.cloud.infrastructure.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.security.dto.RedisDeviceRequestResultDto;
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
public final class RedisStore {
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisScript<Long> rateLimitScript;
    private final RedisScript<List> deviceRequestScript;
    private final ObjectMapper objectMapper;

    public <T> void set(String redisKey, T value, Duration ttl) {
        execute(() -> redisTemplate.opsForValue().set(redisKey, value, ttl));
    }

//    public long increment(String redisKey) {
//        return execute(() -> redisTemplate.opsForValue().increment(redisKey));
//    }
//
//    public boolean expire(String redisKey, Duration ttl) {
//        return execute(() -> redisTemplate.expire(redisKey, ttl));
//    }

    public long incrementWithTtl(String key, Duration ttl) {
        if (ttl.isZero() || ttl.isNegative()) {
            throw new RedisOperationException("TTL must be positive");
        }

        Long value = execute(() -> redisTemplate.execute(
            rateLimitScript,
            List.of(key),
            ttl.getSeconds()
        ));

        if (value == null) {
            throw new RedisOperationException("Rate limit script returned \"null\"");
        }

        return value;
    }

    @SuppressWarnings("unchecked")
    public RedisDeviceRequestResultDto processDeviceRequest(
        String nonceKey,
        String deviceKey,
        String rateLimitKey,
        Duration nonceTtl,
        Duration rateWindowKey,
        int rateLimit
    ) {
        if (nonceTtl.isZero() || nonceTtl.isNegative()) {
            throw new RedisOperationException("nonce TTL must be positive");
        }

        if (rateWindowKey.isZero() || rateWindowKey.isNegative()) {
            throw new RedisOperationException("rate limit TTL must be positive");
        }

        List<Object> raw = execute(() -> (List<Object>) redisTemplate.execute(
            deviceRequestScript,
            List.of(nonceKey, deviceKey, rateLimitKey),
            nonceTtl.getSeconds(),
            rateWindowKey.getSeconds(),
            rateLimit
        ));

        if (raw == null || raw.size() < 4) {
            throw new RedisOperationException("Invalid Redis response");
        }

        String publicKey = (String) raw.get(0);

        boolean revoked = raw.get(1) != null && ((Long) raw.get(1)) == 1L;
        boolean isReplay = ((Long) raw.get(2)) == 1L;
        boolean isRateLimited = ((Long) raw.get(3)) == 1L;

        return new RedisDeviceRequestResultDto(
            publicKey,
            revoked,
            isReplay,
            isRateLimited
        );
    }
    private <T> T convert(Object data, Class<T> clazz) {
        if (data == null) {
            return null;
        }

        try {
            return objectMapper.convertValue(data, clazz);
        } catch (IllegalArgumentException e) {
            throw new RedisOperationException(
                "Failed to convert Redis value to " + clazz.getSimpleName(), e
            );
        }
    }

    @Nullable
    public <T> T get(String key, Class<T> clazz) {
        return convert(execute(() -> redisTemplate.opsForValue().get(key)), clazz);
    }

    @Nullable
    public <T> T getAndDelete(String key, Class<T> clazz) {
        return convert(execute(() -> redisTemplate.opsForValue().getAndDelete(key)), clazz);
    }

    public boolean setIfAbsent(String key, String value, Duration ttl) {
        return execute(() -> Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(key, value, ttl)));
    }

    private <T> T execute(Supplier<T> supplier) {
        try {
            return supplier.get();
        } catch (DataAccessException e) {
            throw new RedisOperationException("Supplier method error: " + e.getMessage(), e);
        }
    }

    private void execute(Runnable action) {
        try {
            action.run();
        } catch (DataAccessException e) {
            throw new RedisOperationException("Runnable method error: " + e.getMessage(), e);
        }
    }
}
