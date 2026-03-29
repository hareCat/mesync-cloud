package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;

import java.security.PublicKey;

public interface SignatureVerifier {
    boolean verify(PublicKey publicKey, byte[] payload, byte[] signature) throws CryptoException;
}
