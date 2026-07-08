package com.iplion.mesync.cloud.security.request.common;

import java.util.UUID;

public interface RegisteredDeviceAuthRequest extends SignedAuthRequest {
    UUID devicePublicId();

}
