package com.iplion.mesync.cloud.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.List;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(
        RedisConnectionFactory redisConnectionFactory,
        ObjectMapper objectMapper
    ) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(
            objectMapper,
            Object.class
        );

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer);
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashValueSerializer(jackson2JsonRedisSerializer);

        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    @Bean
    public RedisScript<Long> rateLimitScript() {
        String script = """
            local current = redis.call("INCR", KEYS[1])
            if current == 1 then
                redis.call("EXPIRE", KEYS[1], ARGV[1])
            end
            return current
            """;

        return RedisScript.of(script, Long.class);
    }

    @Bean
    /**
     * KEYS: 1 - auth key
     * ARGS: 1 - publicKey; 2 - is revoked (0/1); 3 - ttlSeconds (0 = no ttl)
     * returns:
     *      1  - publicKey saved (new device)
     *      0  - already exists (same publicKey)
     *      -1 - invalid request data
     *      -2 - publicKey mismatch
     */
    public RedisScript<Long> saveDeviceScript() {
        String script = """
        local deviceKey = KEYS[1]
        local publicKey = ARGV[1]
        local isRevoked = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
    
        if not publicKey or publicKey == "" or (isRevoked ~= 0 and isRevoked ~= 1) then
            return -1
        end
    
        local savedPublicKey = redis.call("HGET", deviceKey, "publicKey")
    
        local isPublicKeySaved = 0
        if savedPublicKey then
            if savedPublicKey ~= publicKey then
                return -2
            end
        else
            redis.call("HSET", deviceKey, "publicKey", publicKey)
            isPublicKeySaved = 1
        end

        redis.call("HSET", deviceKey, "revoked", isRevoked)
    
        if ttl and ttl > 0 and isPublicKeySaved == 1 then
            redis.call("EXPIRE", deviceKey, ttl)
        end

        return isPublicKeySaved
    """;

        return RedisScript.of(script, Long.class);
    }

    @Bean
    // KEYS: [1] nonce key [2] auth key [3] rate limit key
    // ARGS: [1] nonce TTL [2] rate window TTL [3] rate limit max requests
    public RedisScript<List> authRequestScript() {
        String script = """
            -- auth data --
            local publicKey = redis.call("HGET", KEYS[2], "publicKey")
            local isRevoked = nil
            if publicKey then
                isRevoked = redis.call("HGET", KEYS[2], "revoked")
            end
            
            -- anti-replay (nonce) --
            local isReplay = not redis.call("SET", KEYS[1], "1", "EX", ARGV[1], "NX")
            
            -- rate limit --
            local current
            if not isReplay then
                current = redis.call("INCR", KEYS[3])
                if current == 1 then
                    redis.call("EXPIRE", KEYS[3], tonumber(ARGV[2]))
                end
            else
                current = tonumber(redis.call("GET", KEYS[3]) or "0")
            end
            local isRateLimited = current > tonumber(ARGV[3])
            
            -- summary --
            return {
                  publicKey,                    -- [0]
                  isRevoked,                    -- [1]
                  isReplay and 1 or 0,          -- [2]
                  isRateLimited and 1 or 0      -- [3]
              }
            """;

        return RedisScript.of(script, List.class);
    }

}
