package com.iplion.mesync.cloud.security.auth;

import java.util.UUID;

public interface RegisteredDeviceAuthRequest extends SignedAuthRequest {
    UUID devicePublicId();

}
