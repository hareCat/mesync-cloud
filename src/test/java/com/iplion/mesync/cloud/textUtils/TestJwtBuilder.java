package com.iplion.mesync.cloud.textUtils;

import com.iplion.mesync.cloud.model.DeviceType;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public class TestJwtBuilder {
    private final Jwt.Builder builder;

    private TestJwtBuilder(Jwt.Builder builder) {
        this.builder = builder;
    }

    public static TestJwtBuilder custom() {
        return new TestJwtBuilder(Jwt.withTokenValue("token"))
            .header("alg", "none")
            .claim("some", "value");
    }

    public static TestJwtBuilder forDevice(UUID authId, DeviceType deviceType) {
        return custom().withSubject(authId).withDeviceType(deviceType);
    }

    public TestJwtBuilder withSubject(UUID authId) {
        return this.subject(authId.toString());
    }

    public TestJwtBuilder withEmail(String email) {
        return this.claim("email", email);
    }

    public TestJwtBuilder withEmailVerified(boolean emailVerified) {
        return this.claim("email_verified", emailVerified);
    }

    public TestJwtBuilder withDeviceType(DeviceType deviceType) {
        return this.claim("azp", deviceType.getClientId());
    }

    public TestJwtBuilder subject(String raw) {
        builder.subject(raw);
        return this;
    }

    public TestJwtBuilder claim(String claimName, Object claimValue) {
        builder.claim(claimName, claimValue);
        return this;
    }

    public TestJwtBuilder header(String headerName, String headerValue) {
        builder.header(headerName, headerValue);
        return this;
    }

    public Jwt build() {
        return builder.build();
    }
}
