package com.iplion.mesync.cloud.security.request;

public interface UnregisteredDeviceAuthRequest extends SignedAuthRequest {
    String base64SigningPublicKey();

}
