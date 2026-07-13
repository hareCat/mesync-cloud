package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilsTest {
    private static final UUID TEST_SUBJECT_UUID = UUID.randomUUID();
    private static final DeviceType TEST_DEVICE_TYPE = DeviceType.BROWSER;

    @Test
    void extractSubjectUuid_returnsParsedUuid() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .buildJwt();

        assertThat(JwtUtils.extractSubjectUuid(jwt))
            .isEqualTo(TEST_SUBJECT_UUID);
    }

    @ParameterizedTest
    @MethodSource("missingOrBlankSubjectJwts")
    void extractSubjectUuid_throwsForMissingOrBlankSubject(Jwt jwt) {
        assertThatThrownBy(() -> JwtUtils.extractSubjectUuid(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractSubjectUuid_throwsForInvalidUuid() {
        Jwt jwt = TestJwtBuilder.custom().subject("not-uuid").buildJwt();

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
            .buildJwt();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.authId()).isEqualTo(TEST_SUBJECT_UUID);
        assertThat(result.clientId()).isEqualTo(TEST_DEVICE_TYPE.getClientId());
        assertThat(result.email()).isEqualTo(normalizedEmail);
        assertThat(result.emailVerified()).isTrue();
    }

    @Test
    void extractUserData_returnsNullEmailAndNotVerifiedForMissingClaims() {
        Jwt jwt = TestJwtBuilder.custom()
            .withSubject(TEST_SUBJECT_UUID)
            .withDeviceType(TEST_DEVICE_TYPE)
            .buildJwt();

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
            .buildJwt();

        JwtUserData result = JwtUtils.extractUserData(jwt);

        assertThat(result.emailVerified()).isFalse();
    }

    @ParameterizedTest
    @MethodSource("missingOrBlankClientIdJwts")
    void extractUserData_throwsForMissingOrBlankClientId(Jwt jwt) {
        assertThatThrownBy(() -> JwtUtils.extractUserData(jwt))
            .isInstanceOf(InvalidTokenException.class);
    }

    static Stream<Jwt> missingOrBlankSubjectJwts() {
        return Stream.of(
            TestJwtBuilder.custom().buildJwt(),
            TestJwtBuilder.custom().subject("  ").buildJwt()
        );
    }

    static Stream<Jwt> missingOrBlankClientIdJwts() {
        return Stream.of(
            TestJwtBuilder.custom()
                .withSubject(TEST_SUBJECT_UUID)
                .buildJwt(),
            TestJwtBuilder.custom()
                .withSubject(TEST_SUBJECT_UUID)
                .claim("azp", "  ")
                .buildJwt()
        );
    }
}
