package com.iplion.mesync.cloud.security.crypto;

import java.security.PublicKey;

public interface KeySignatureService {
    void verify(PublicKey publicKey, byte[] payload, byte[] signature);

    PublicKey createPublicKey(byte[] publicKeyBytes);

    byte[] extractPublicKeyBytes(PublicKey publicKey);
}
