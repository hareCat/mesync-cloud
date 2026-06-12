package com.iplion.mesync.cloud.testUtils;

import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.SecurityContextUtils;
import com.iplion.mesync.cloud.security.cache.AuthData;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.UUID;

public final class TestSecurity {
    public static void createSecurityContext(AuthData authData) {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(
            TestJwtBuilder.forDevice(UUID.randomUUID(), DeviceType.MOBILE).buildJwt()
        ));
        SecurityContextUtils.setAuthData(authData);
    }
}
