package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.model.JwtUserData;

public interface AuthResult {
    JwtUserData jwtUserData();
}
