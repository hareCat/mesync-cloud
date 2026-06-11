package com.iplion.mesync.cloud.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@ConfigurationProperties("app")
@Validated
public record AppProperties(
    @Valid Registration registration,
    @Valid Auth auth,
    @Valid Revoke revoke,
    @Valid Cache cache
) {
    public record Registration(
        @NotNull Duration inviteTtl,
        @NotNull Duration inviteCooldown,

        @NotNull Duration nonceTtl,
        @NotNull Duration rateLimitTtl,
        @Min(1) int attempts
    ) {}

    public record Auth(
        @NotNull Duration nonceTtl,
        @NotNull Duration rateLimitTtl,
        @Min(1) int attempts
    ) {}

    public record Revoke(
        @NotNull Duration ttl
    ) {}

    public record Cache(
        @NotNull Duration ttl,
        int userCacheSize,
        int deviceCacheSize
    ) {}

}