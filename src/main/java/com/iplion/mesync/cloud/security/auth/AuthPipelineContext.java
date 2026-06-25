package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.cache.AuthData;
import lombok.Data;

import java.util.UUID;

@Data
public class AuthPipelineContext<T extends SignedAuthRequest> {
    private final T request;
    JwtUserData jwtUserData;
    UUID securitySubjectId;
    AuthData authData;
}
