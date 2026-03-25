package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.model.JwtUserData;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Locale;
import java.util.UUID;

public final class JwtUtils {
    private JwtUtils() {}

    public static JwtUserData extractUserData(@NotNull Jwt jwt) {
        return new JwtUserData(
            extractSubjectUuid(jwt),
            extractClientId(jwt),
            extractEmail(jwt),
            isEmailVerified(jwt)
        );
    }

    public static UUID extractSubjectUuid(@NotNull Jwt jwt) {
        String subject = jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new InvalidTokenException("JWT subject is missing");
        }

        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("JWT subject is not a valid UUID", e);
        }
    }

    private static String extractEmail(@NotNull Jwt jwt) {
        String email = jwt.getClaimAsString("email");

        return (email == null || email.isBlank()) ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    private static String extractClientId(@NotNull Jwt jwt) {
        String clientId = jwt.getClaimAsString("azp");
        if (clientId == null || clientId.isBlank()) {
            throw new InvalidTokenException("Client id (azp) is missing");
        }

        return clientId;
    }

    private static boolean isEmailVerified(@NotNull Jwt jwt) {
        return Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified"));
    }
}
