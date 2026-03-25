package com.iplion.mesync.cloud.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@ConfigurationProperties("app.registration")
@Validated
public record RegistrationProperties(

    @NotNull Duration inviteTtl,
    @NotNull Duration inviteCooldown,

    @NotNull Duration registrationTtl,
    @Min(1) int registrationAttempts

) {
}