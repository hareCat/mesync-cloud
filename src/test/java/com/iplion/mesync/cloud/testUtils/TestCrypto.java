package com.iplion.mesync.cloud.testUtils;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;

public final class TestCrypto {

    private static final String ALGORITHM = "Ed25519";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
    }

    public static byte[] sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM);

        signature.initSign(privateKey);
        signature.update(payload);

        return signature.sign();
    }

}