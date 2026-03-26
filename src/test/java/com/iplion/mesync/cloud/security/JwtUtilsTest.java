package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.model.JwtUserData;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilsTest {
    private final UUID TEST_SUBJECT_UUID = UUID.randomUUID();
    private final String TEST_CLIENT_ID = "mesync-test";

    @Test
    void extractSubjectUuid_returnsParsedUuid() {
        Jwt jwt = jwtHeaderClaimBuilder()
            .claim("azp", "mesync-test")
            .subject(TEST_SUBJECT_UUID.toString())
            .build();

        assertThat(JwtUtils.extractSubjectUuid(jwt))
            .isEqualTo(TEST_SUBJECT_UUID);
    }

    @Test
    void extractSubjectUuid_throwsForMissingSubject() {
        Jwt jwt = jwtHeaderClaimBuilder().build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractSubjectUuid_throwsForBlankSubject() {
        Jwt jwt = jwtHeaderClaimBuilder().subject("  ").build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractSubjectUuid_throwsForInvalidUuid() {
        Jwt jwt = jwtHeaderClaimBuilder().subject("not-uuid").build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class)
            .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void extractUserData_returnsJwtUserData() {
        String email = "tEst07@MAIL.cOm";
        String normalizedEmail = "test07@mail.com";

        Map<String, Object> claims = Map.of(
            "email", email,
            "email_verified", true,
            "azp", TEST_CLIENT_ID
        );

        JwtUserData jwtUserData = new JwtUserData(
            TEST_SUBJECT_UUID,
            TEST_CLIENT_ID,
            normalizedEmail,
            true
        );

        Jwt jwt = jwtHeaderClaimBuilder()
            .subject(TEST_SUBJECT_UUID.toString())
            .claims(c -> c.putAll(claims))
            .build();

        assertThat(JwtUtils.extractUserData(jwt))
            .isEqualTo(jwtUserData);
    }

    @Test
    void extractUserData_returnsNullEmailAndNotVerifiedForMissingClaims() {
        Jwt jwt = jwtHeaderClaimBuilder()
            .subject(TEST_SUBJECT_UUID.toString())
            .claim("azp", TEST_CLIENT_ID)
            .build();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.email()).isNull();
        assertThat(result.emailVerified()).isFalse();
    }

    @Test
    void extractUserData_returnsFalseEmailVerified() {
        Jwt jwt = jwtHeaderClaimBuilder()
            .subject(TEST_SUBJECT_UUID.toString())
            .claim("azp", TEST_CLIENT_ID)
            .claim("email_verified", false)
            .build();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.emailVerified()).isFalse();
    }

    @Test
    void extractUserData_throwsForBlankClientId() {
        Jwt jwt = jwtHeaderClaimBuilder()
            .subject(TEST_SUBJECT_UUID.toString())
            .claim("azp", "  ")
            .build();

        assertThatThrownBy(() -> JwtUtils.extractUserData(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractUserData_throwsForMissingClientId() {
        Jwt jwt = jwtHeaderClaimBuilder()
            .subject(TEST_SUBJECT_UUID.toString())
            .build();

        assertThatThrownBy(() -> JwtUtils.extractUserData(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    private static Jwt.Builder jwtHeaderClaimBuilder() {
        return Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim("some", "value");
    }
}
