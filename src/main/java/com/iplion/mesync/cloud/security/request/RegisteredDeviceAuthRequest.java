package com.iplion.mesync.cloud.security.request;

import java.util.UUID;

public interface RegisteredDeviceAuthRequest extends SignedAuthRequest {
    UUID devicePublicId();

}
