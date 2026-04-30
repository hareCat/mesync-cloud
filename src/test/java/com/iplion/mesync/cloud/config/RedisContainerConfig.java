package com.iplion.mesync.cloud.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;

@TestConfiguration
public class RedisContainerConfig {
    @Bean
    @ServiceConnection(name = "redis")
    public GenericContainer<?> redis() {
        return new GenericContainer<>("redis:8.4.0")
            .withExposedPorts(6379);
    }

}
