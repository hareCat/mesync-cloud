package com.iplion.mesync.cloud.security.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.error.AuthException;
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
    private final RedisScript<Long> registrationSecurityCheckScript;
    private final RedisScript<Long> deviceAuthSecurityCheckScript;
    private final ObjectMapper objectMapper;

    public <T> void set(String redisKey, T value, Duration ttl) {
        execute(() -> redisTemplate.opsForValue().set(redisKey, value, ttl));
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

    public void deviceAuthSecurityCheck(
        String deviceRevokedKey,
        String nonceKey,
        String rateLimitKey,
        Duration nonceTtl,
        Duration rateLimitTtl,
        int rateLimit
    ) {
        validateSecurityLimits(nonceTtl, rateLimitTtl, rateLimit);

        Long value = execute(() -> redisTemplate.execute(
            deviceAuthSecurityCheckScript,
            List.of(nonceKey, rateLimitKey, deviceRevokedKey),
            nonceTtl.getSeconds(),
            rateLimitTtl.getSeconds(),
            rateLimit
        ));

        if (value == null) {
            throw new RedisOperationException("Invalid Redis response");
        }

        switch (value.intValue()) {
            case 0 -> {}
            case -1 -> throw AuthException.replay(nonceKey);
            case -2 -> throw AuthException.rateLimit(rateLimitKey);
            case -3 -> throw AuthException.revoked(deviceRevokedKey);
            default -> throw new RedisOperationException("Unknown Redis response: " + value);
        }
    }

    public void registrationSecurityCheck(
        String nonceKey,
        String rateLimitKey,
        Duration nonceTtl,
        Duration rateLimitTtl,
        int rateLimit
    ) {
        validateSecurityLimits(nonceTtl, rateLimitTtl, rateLimit);

        Long value = execute(() -> redisTemplate.execute(
            registrationSecurityCheckScript,
            List.of(nonceKey, rateLimitKey),
            nonceTtl.getSeconds(),
            rateLimitTtl.getSeconds(),
            rateLimit
        ));

        if (value == null) {
            throw new RedisOperationException("Invalid Redis response");
        }

        switch (value.intValue()) {
            case 0 -> {}
            case -1 -> throw AuthException.replay(nonceKey);
            case -2 -> throw AuthException.rateLimit(rateLimitKey);
            default -> throw new RedisOperationException("Unknown Redis response: " + value);
        }
    }

    private void validateSecurityLimits(
        Duration nonceTtl,
        Duration rateWindowTtl,
        int rateLimit
    ) {
        if (nonceTtl.isZero() || nonceTtl.isNegative()) {
            throw new RedisOperationException("nonce TTL must be positive. TTL: " + nonceTtl);
        }

        if (rateWindowTtl.isZero() || rateWindowTtl.isNegative()) {
            throw new RedisOperationException("rate limit TTL must be positive. TTL: " + rateWindowTtl);
        }

        if (rateLimit <= 0) {
            throw new RedisOperationException("rate limit must be positive. rateLimit: " + rateLimit);
        }
    }

}
