package com.iplion.mesync.cloud.security.crypto;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class Ed25519SignatureVerifierTest {

    private final Ed25519SignatureVerifier verifier = new Ed25519SignatureVerifier();

    @Test
    public void verify_whenWrongTypeOfPublicKey_shouldThrowInvalidPublicKeyException() {
        assertThatThrownBy(() -> verifier.verify(mock(PublicKey.class), new byte[4], new byte[44]))
            .isInstanceOf(InvalidPublicKeyException.class);
    }

    @Test
    public void verify_whenInvalidSignature_shouldThrowCryptoException() throws Exception {
        PublicKey publicKey = generateEd25519Key();

        assertThatThrownBy(() -> verifier.verify(publicKey, new byte[4], new byte[10]))
            .isInstanceOf(CryptoException.class);
    }

    @Test
    public void verify_whenSignatureValid_shouldReturnTrue() throws Exception {
        var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(keyPair.getPrivate());
        sig.update(payload);
        byte[] signature = sig.sign();

        assertThat(verifier.verify(keyPair.getPublic(), payload, signature)).isTrue();
    }

    @Test
    public void verify_whenSignatureNotValid_shouldReturnFalse() throws Exception {
        var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = new byte[64];

        assertThat(verifier.verify(keyPair.getPublic(), payload, signature)).isFalse();
    }


    private PublicKey generateEd25519Key() throws Exception {
        return KeyPairGenerator
            .getInstance("Ed25519")
            .generateKeyPair()
            .getPublic();
    }


//    @Test
//    void verifyReturnsTrueForValidSignature() throws Exception {
//        KeyPair keyPair = generateEd25519KeyPair();
//        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
//        String signature = signToBase64(keyPair, payload);
//
//        assertThat(Ed25519SignatureVerifier.verify(keyPair.getPublic(), payload, signature)).isTrue();
//    }
//
//    @Test
//    void verifyReturnsFalseForDifferentPayload() throws Exception {
//        KeyPair keyPair = generateEd25519KeyPair();
//        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
//        String signature = signToBase64(keyPair, payload);
//
//        assertThat(Ed25519SignatureVerifier.verify(
//            keyPair.getPublic(),
//            "other".getBytes(StandardCharsets.UTF_8),
//            signature
//        )).isFalse();
//    }
//
//    @Test
//    void verifyThrowsForNonEd25519Key() {
//        PublicKey publicKey = new PublicKey() {
//            @Override
//            public String getAlgorithm() {
//                return "RSA";
//            }
//
//            @Override
//            public String getFormat() {
//                return "X.509";
//            }
//
//            @Override
//            public byte[] getEncoded() {
//                return new byte[0];
//            }
//        };
//
//        assertThatThrownBy(() -> Ed25519SignatureVerifier.verify(publicKey, new byte[0], Base64.getEncoder().encodeToString(new byte[64])))
//            .isInstanceOf(InvalidPublicKeyException.class)
//            .hasMessageContaining("Expected Ed25519 key");
//    }
//
//    @Test
//    void parseSignatureThrowsForInvalidBase64() {
//        assertThatThrownBy(() -> Ed25519SignatureVerifier.parseSignature("%%%"))
//            .isInstanceOf(CryptoException.class)
//            .hasMessageContaining("Invalid base64 signature");
//    }
//
//    @Test
//    void parseSignatureThrowsForWrongLength() {
//        String signature = Base64.getEncoder().encodeToString(new byte[63]);
//
//        assertThatThrownBy(() -> Ed25519SignatureVerifier.parseSignature(signature))
//            .isInstanceOf(CryptoException.class)
//            .hasMessageContaining("Wrong signature length");
//    }
//
//    private static KeyPair generateEd25519KeyPair() throws Exception {
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
//        return generator.generateKeyPair();
//    }
//
//    private static String signToBase64(KeyPair keyPair, byte[] payload) throws Exception {
//        Signature signature = Signature.getInstance("Ed25519");
//        signature.initSign(keyPair.getPrivate());
//        signature.update(payload);
//        return Base64.getEncoder().encodeToString(signature.sign());
//    }
}
