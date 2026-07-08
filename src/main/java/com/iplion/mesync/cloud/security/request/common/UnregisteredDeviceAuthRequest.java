package com.iplion.mesync.cloud.security.request.common;

public interface UnregisteredDeviceAuthRequest extends SignedAuthRequest {
    String base64SigningPublicKey();

}
