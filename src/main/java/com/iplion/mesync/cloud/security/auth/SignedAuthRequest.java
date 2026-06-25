package com.iplion.mesync.cloud.security.auth;

import java.util.UUID;

public interface SignedAuthRequest {
    String base64Signature();

    UUID nonce();

    byte[] payload();

}
