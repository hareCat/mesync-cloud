package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.request.common.SignedAuthRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
class AuthPipelineContext<T extends SignedAuthRequest> {
    @Getter
    private final T request;

    @Getter
    @Setter
    JwtUserData jwtUserData;

    @Getter
    @Setter
    AuthData authData;
}
