package com.iplion.mesync.cloud.security.auth;

public interface PublicKeyAuthRequest extends AuthRequest {
    String base64PublicKey();

}
