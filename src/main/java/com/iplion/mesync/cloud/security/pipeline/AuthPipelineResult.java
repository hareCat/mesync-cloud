package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.cache.AuthData;

public record AuthPipelineResult(
    AuthData authData,
    JwtUserData jwtUserData
) {
}
