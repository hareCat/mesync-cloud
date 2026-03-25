package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public final class Ed25519SignatureVerifier {
    private static final int ED25519_SIGNATURE_LENGTH = 64;

    private Ed25519SignatureVerifier() {}

    public static boolean verify(PublicKey publicKey, byte[] payloadBytes, String base64Signature) {
        return verify(publicKey, payloadBytes, parseSignature(base64Signature));
    }

    public static boolean verify(PublicKey publicKey, byte[] payloadBytes, byte[] signatureBytes) {
        if (!"Ed25519".equals(publicKey.getAlgorithm())) {
            throw new InvalidPublicKeyException("Expected Ed25519 key");
        }

        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(payloadBytes);

            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Signature verification process failed", e);
        }
    }

    public static byte[] parseSignature(String base64Signature) {
        byte[] signatureBytes;

        try {
            signatureBytes = Base64.getDecoder().decode(base64Signature);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid base64 signature", e);
        }

        if (signatureBytes.length != ED25519_SIGNATURE_LENGTH) {
            throw new CryptoException("Wrong signature length");
        }

        return signatureBytes;
    }
}
