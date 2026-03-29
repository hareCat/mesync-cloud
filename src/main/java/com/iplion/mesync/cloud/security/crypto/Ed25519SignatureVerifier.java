package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

@Component
public final class Ed25519SignatureVerifier implements SignatureVerifier {

    private static final String ALGORITHM = "Ed25519";
    private static final int ALGORITHM_SIGNATURE_LENGTH = 64;

    @Override
    public boolean verify(PublicKey publicKey, byte[] payloadBytes, byte[] signatureBytes) {

        if (!ALGORITHM.equals(publicKey.getAlgorithm())) {
            throw new InvalidPublicKeyException("Expected Ed25519 key");
        }

        if (signatureBytes.length != ALGORITHM_SIGNATURE_LENGTH) {
            throw new CryptoException("Wrong signature length");
        }

        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(payloadBytes);

            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Signature verification process failed", e);
        }
    }
}