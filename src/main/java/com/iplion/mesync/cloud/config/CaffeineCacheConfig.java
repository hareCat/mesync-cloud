package com.iplion.mesync.cloud.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class CaffeineCacheConfig {
    private final AppProperties props;

    @Bean
    public Cache<UUID, DeviceAuthData> deviceAuthCache() {
        return Caffeine.newBuilder()
            .maximumSize(props.cache().deviceCacheSize())
            .expireAfterAccess(props.cache().ttl())
            .build();
    }

    @Bean
    public Cache<UUID, UserAuthData> userAuthCache() {
        return Caffeine.newBuilder()
            .maximumSize(props.cache().userCacheSize())
            .expireAfterAccess(props.cache().ttl())
            .build();
    }

}
