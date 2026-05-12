package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class Ed25519KeySignatureServiceTest {
    private Ed25519KeySignatureService keyService;

    @BeforeEach
    void setUp() throws Exception {
        keyService = new Ed25519KeySignatureService(
            KeyFactory.getInstance("Ed25519")
        );
    }

    @Test
    public void verify_whenWrongTypeOfPublicKey_shouldThrowInvalidPublicKeyException() {
        assertThatThrownBy(() -> keyService.verify(mock(PublicKey.class), new byte[4], new byte[44]))
            .isInstanceOf(InvalidPublicKeyException.class);
    }

    @Test
    public void verify_whenInvalidSignature_shouldThrowCryptoException() throws Exception {
        PublicKey publicKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();

        assertThatThrownBy(() -> keyService.verify(publicKey, new byte[4], new byte[10]))
            .isInstanceOf(CryptoException.class);
    }

    @Test
    public void verify_whenSignatureValid_shouldPassVerification() throws Exception {
        var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(keyPair.getPrivate());
        sig.update(payload);
        byte[] signature = sig.sign();

        assertThatCode(() -> keyService.verify(keyPair.getPublic(), payload, signature))
            .doesNotThrowAnyException();
    }

    @Test
    public void verify_whenSignatureNotValid_shouldThrowCryptoExceptionWithoutCause() throws Exception {
        PublicKey publicKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] invalidSignature = new byte[64];

        assertThatThrownBy(() -> keyService.verify(publicKey, payload, invalidSignature))
            .isInstanceOf(CryptoException.class)
            .hasNoCause();
    }

    @Test
    void createPublicKey_whenValidBytes_shouldRestoreKey() throws Exception {
        byte[] encoded = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();

        PublicKey createdPublicKey = keyService.createPublicKey(encoded);

        assertThat(createdPublicKey.getEncoded()).isEqualTo(encoded);
    }


    @Test
    void createPublicKey_whenInvalidBytes_shouldThrowInvalidPublicKeyException() throws Exception {
        byte[] invalidBytes = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic().getEncoded();

        assertThatThrownBy(() -> keyService.createPublicKey(invalidBytes))
            .isInstanceOf(InvalidPublicKeyException.class)
            .hasCauseInstanceOf(GeneralSecurityException.class);
    }


    @Test
    void extractPublicKeyBytes_whenValidKey_shouldReturnEncodedBytes() throws Exception {
        PublicKey publicKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();

        byte[] extracted = keyService.extractPublicKeyBytes(publicKey);

        assertThat(extracted).isEqualTo(publicKey.getEncoded());
    }


    @Test
    void extractPublicKeyBytes_whenWrongKeyType_shouldThrowInvalidPublicKeyException() throws Exception {
        PublicKey publicKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();

        assertThatThrownBy(() -> keyService.extractPublicKeyBytes(publicKey))
            .isInstanceOf(InvalidPublicKeyException.class)
            .hasNoCause();
    }

}
