package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SecurityContextUtilsTest {


    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @Test
    void getJwt_shouldReturnJwtFromSecurityContext() {
        Jwt jwt = jwt();
        setJwtToken(jwt);

        Jwt result = SecurityContextUtils.getJwt();

        assertThat(result).isEqualTo(jwt);
    }

    @Test
    void getJwt_shouldThrowWhenJwtIsNotAvailable() {
        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken(
                "principal",
                null
            )
        );

        assertThatThrownBy(SecurityContextUtils::getJwt)
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("JWT");
    }

    // --------------------------- helpers -----------------------------------------

    private Jwt jwt() {
        return TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE).buildJwt();
    }

    private void setJwtToken(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
