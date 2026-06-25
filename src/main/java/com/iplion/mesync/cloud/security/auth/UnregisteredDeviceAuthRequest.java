package com.iplion.mesync.cloud.security.auth;

public interface UnregisteredDeviceAuthRequest extends SignedAuthRequest {
    String base64SigningPublicKey();

}
