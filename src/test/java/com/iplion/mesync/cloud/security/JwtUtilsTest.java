package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.textUtils.TestJwtBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilsTest {
    private final UUID TEST_SUBJECT_UUID = UUID.randomUUID();
    private final DeviceType TEST_DEVICE_TYPE = DeviceType.BROWSER;

    @Test
    void extractSubjectUuid_returnsParsedUuid() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .build();

        assertThat(JwtUtils.extractSubjectUuid(jwt))
            .isEqualTo(TEST_SUBJECT_UUID);
    }

    @Test
    void extractSubjectUuid_throwsForMissingSubject() {
        Jwt jwt = TestJwtBuilder.custom().build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractSubjectUuid_throwsForBlankSubject() {
        Jwt jwt = TestJwtBuilder.custom().subject("  ").build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractSubjectUuid_throwsForInvalidUuid() {
        Jwt jwt = TestJwtBuilder.custom().subject("not-uuid").build();

        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class)
            .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void extractUserData_returnsJwtUserData() {
        String email = "tEst07@MAIL.cOm";
        String normalizedEmail = "test07@mail.com";

        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .withEmail(email)
            .withEmailVerified(true)
            .withDeviceType(TEST_DEVICE_TYPE)
            .build();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.id()).isEqualTo(TEST_SUBJECT_UUID);
        assertThat(result.clientId()).isEqualTo(TEST_DEVICE_TYPE.getClientId());
        assertThat(result.email()).isEqualTo(normalizedEmail);
        assertThat(result.emailVerified()).isTrue();
    }

    @Test
    void extractUserData_returnsNullEmailAndNotVerifiedForMissingClaims() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .withDeviceType(TEST_DEVICE_TYPE)
            .build();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.email()).isNull();
        assertThat(result.emailVerified()).isFalse();
    }

    @Test
    void extractUserData_setsEmailVerifiedFalseWhenClaimIsFalse() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .withDeviceType(TEST_DEVICE_TYPE)
            .withEmailVerified(false)
            .build();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.emailVerified()).isFalse();
    }

    @Test
    void extractUserData_throwsForBlankClientId() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .claim("azp", "  ")
            .build();

        assertThatThrownBy(() -> JwtUtils.extractUserData(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractUserData_throwsForMissingClientId() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .build();

        assertThatThrownBy(() -> JwtUtils.extractUserData(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }
}
