package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.X509EncodedKeySpec;

@Service
@RequiredArgsConstructor
public final class Ed25519KeySignatureService implements KeySignatureService {
    private static final String ALGORITHM = "Ed25519";
    private static final int SIGNATURE_LENGTH = 64;

    private final KeyFactory keyFactory;

    @Override
    public void verify(PublicKey publicKey, byte[] payloadBytes, byte[] signatureBytes) {
        validatePublicKey(publicKey);

        if (signatureBytes.length != SIGNATURE_LENGTH) {
            throw new CryptoException("Invalid signature");
        }

        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(payloadBytes);

            if (!signature.verify(signatureBytes)) {
                throw new CryptoException("Signature verification rejected.");
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ALGORITHM + " signature verification failed", e);
        }

    }

    @Override
    public PublicKey createPublicKey(byte[] publicKeyBytes) {
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (GeneralSecurityException e) {
            throw new InvalidPublicKeyException("Public key generation error", e);
        }
    }

    @Override
    public byte[] extractPublicKeyBytes(PublicKey publicKey) {
        validatePublicKey(publicKey);

        return publicKey.getEncoded();
    }

    private void validatePublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof EdECPublicKey)) {
            throw new InvalidPublicKeyException("Expected Ed25519 key");
        }
    }
}