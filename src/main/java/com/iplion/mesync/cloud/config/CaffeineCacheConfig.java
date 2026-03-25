package com.iplion.mesync.cloud.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class CaffeineCacheConfig {
    private static final int DEVICE_PUBLIC_KEY_CACHE_SIZE = 100_000;
    private static final Duration DEVICE_PUBLIC_KEY_CACHE_TTL = Duration.ofHours(12);

    @Bean
    public Cache<UUID, PublicKey> devicePublicKeyCache() {
        return Caffeine.newBuilder()
            .maximumSize(DEVICE_PUBLIC_KEY_CACHE_SIZE)
            .expireAfterAccess(DEVICE_PUBLIC_KEY_CACHE_TTL)
            .build();
    }

}
