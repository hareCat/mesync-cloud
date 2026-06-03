package com.iplion.mesync.cloud.security.auth;

import java.util.UUID;

public interface DeviceAuthRequest extends AuthRequest {
    UUID devicePublicId();

}
