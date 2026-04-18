package com.iplion.mesync.cloud.testUtils;

import com.iplion.mesync.cloud.model.DeviceType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class TestJwtBuilder {
    private final Map<String, Object> claims = new HashMap<>();
    private final Map<String, Object> headers = new HashMap<>();
    private String subject;

    private TestJwtBuilder() {}

    public static TestJwtBuilder custom() {
        return new TestJwtBuilder()
            .header("alg", "none")
            .claim("some", "value");
    }

    public static TestJwtBuilder forDevice(UUID authId, DeviceType deviceType) {
        return custom().withSubject(authId).withDeviceType(deviceType);
    }

    public TestJwtBuilder withSubject(UUID authId) {
        return subject(authId.toString());
    }

    public TestJwtBuilder withEmail(String email) {
        return claim("email", email);
    }

    public TestJwtBuilder withEmailVerified(boolean emailVerified) {
        return claim("email_verified", emailVerified);
    }

    public TestJwtBuilder withDeviceType(DeviceType deviceType) {
        return claim("azp", deviceType.getClientId());
    }

    public TestJwtBuilder subject(String raw) {
        subject = raw;
        return this;
    }

    public TestJwtBuilder claim(String claimName, Object claimValue) {
        claims.put(claimName, claimValue);
        return this;
    }

    public TestJwtBuilder header(String headerName, String headerValue) {
        headers.put(headerName, headerValue);
        return this;
    }

    public Jwt buildJwt() {
        Jwt.Builder builder = Jwt.withTokenValue("token")
            .claims(c -> c.putAll(claims))
            .headers(c -> c.putAll(headers));

        if (subject != null && !subject.isEmpty()) {
            builder.subject(subject);
        }

        return builder.build();
    }

    public SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor buildMockMvcJwt() {
        return SecurityMockMvcRequestPostProcessors.jwt()
            .jwt(jwt -> {
                jwt.subject(subject);
                claims.forEach(jwt::claim);
                headers.forEach(jwt::header);
            });
    }
}
