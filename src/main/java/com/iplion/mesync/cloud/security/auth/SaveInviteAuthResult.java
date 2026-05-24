package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.JwtUserData;

public record SaveInviteAuthResult(
    JwtUserData jwtUserData,
    DeviceAuthData deviceAuthData
) {
}
