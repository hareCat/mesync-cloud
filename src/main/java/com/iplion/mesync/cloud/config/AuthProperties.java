package com.iplion.mesync.cloud.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@ConfigurationProperties("app.auth")
@Validated
public record AuthProperties(
    @NotNull Duration nonceTtl,
    @NotNull Duration rateLimitTtl,
    @Min(1) int attempts

) {
}