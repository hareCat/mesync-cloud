package com.iplion.mesync.cloud.security.auth;

import java.util.UUID;

public interface AuthRequest {
    String base64Signature();

    UUID nonce();

    byte[] payload();

}
