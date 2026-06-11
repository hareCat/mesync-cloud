package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

public class SecurityContextUtilsTest {


    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
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

    @Test
    void getAuthData_shouldReturnAuthDataFromSecurityContext() {
        AuthData authData = mock(AuthData.class);
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(jwt());
        authToken.setDetails(authData);

        SecurityContextHolder.getContext().setAuthentication(authToken);

        var result = SecurityContextUtils.getAuthData();

        assertThat(result).isEqualTo(authData);
    }

    @Test
    void getAuthData_shouldThrowWhenAuthDataIsNotAvailable() {
        setJwtToken();

        assertThatThrownBy(SecurityContextUtils::getAuthData)
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("AuthData");
    }

    @Test
    void setAuthData_shouldSaveAuthDataToSecurityContext() {
        AuthData authData = mock(AuthData.class);
        setJwtToken();

        SecurityContextUtils.setAuthData(authData);

        var contextAuthData = SecurityContextHolder.getContext().getAuthentication().getDetails();

        assertThat(contextAuthData).isEqualTo(authData);
    }

    @Test
    void setAuthData_shouldThrowWhenAuthenticationTokenIsNotAvailable() {
        assertThatThrownBy(() -> SecurityContextUtils.setAuthData(mock(AuthData.class)))
            .isInstanceOf(AuthException.class)
            .hasMessageContaining("token");
    }

    // helpers -----------------------------------------

    private Jwt jwt() {
        return TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE).buildJwt();
    }

    private void setJwtToken() {
        setJwtToken(jwt());
    }

    private void setJwtToken(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
