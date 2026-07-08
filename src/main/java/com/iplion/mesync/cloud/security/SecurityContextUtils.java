package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.error.api.AuthException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

public final class SecurityContextUtils {
    private SecurityContextUtils() {}

    public static Jwt getJwt() {
        if (!(getAuthToken().getPrincipal() instanceof Jwt jwt)) {
            throw AuthException.securityContextError("JWT is not available");
        }

        return jwt;
    }

    private static AbstractAuthenticationToken getAuthToken() {
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AbstractAuthenticationToken token)) {
            throw AuthException.securityContextError("Authentication token not found");
        }

        return token;
    }

}
