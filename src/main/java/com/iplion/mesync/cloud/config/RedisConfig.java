package com.iplion.mesync.cloud.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

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

    /** KEYS: [1] nonce key [2] rate limit key
     *  ARGS: [1] nonce TTL [2] rate limit TTL [3] rate limit max requests
     *  returns: [0] - security check passed; [-1] - replay; [-2] - rate limited;
     */
    private static final String COMMON_SECURITY_SCRIPT = """
            -- anti-replay (nonce) --
            if not redis.call("SET", KEYS[1], "1", "EX", ARGV[1], "NX") then
                return -1
            end
            
            -- rate limit --
            local current = redis.call("INCR", KEYS[2])
            if current == 1 then
                redis.call("EXPIRE", KEYS[2], ARGV[2])
            end
            if current > tonumber(ARGV[3]) then
                return -2
            end
            """;

    /**
     *  KEYS: [1] nonce key [2] rate limit key [3] auth key
     *  ARGS: [1] nonce TTL [2] rate limit TTL [3] rate limit max requests
     *  returns: [0] - security check passed; [-1] - replay; [-2] - rate limited;
     */
    @Bean
    public RedisScript<Long> registrationSecurityCheckScript() {
        String script = COMMON_SECURITY_SCRIPT + "\nreturn 0";

        return RedisScript.of(script, Long.class);
    }

    /**
     *  KEYS: [1] nonce key [2] rate limit key [3] auth key
     *  ARGS: [1] nonce TTL [2] rate limit TTL [3] rate limit max requests
     *  returns: [0] - security check passed; [-1] - replay; [-2] - rate limited; [-3]  - revoked;
     */
    @Bean
    public RedisScript<Long> deviceAuthSecurityCheckScript() {
        String script = COMMON_SECURITY_SCRIPT + """
            -- auth data --
            if redis.call("EXISTS", KEYS[3]) == 1 then
                return -3
            end
            
            return 0
            """;

        return RedisScript.of(script, Long.class);
    }

}
