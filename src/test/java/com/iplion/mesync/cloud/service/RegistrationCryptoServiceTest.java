package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.model.DeviceRegistrationVerificationData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.crypto.SignatureVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RegistrationCryptoServiceTest {
    @Mock
    DevicePublicKeyService devicePublicKeyService;

    @Mock
    SignatureVerifier signatureVerifier;

    @InjectMocks
    RegistrationCryptoService registrationCryptoService;


    @Test
    void whenDecodePublicKeyFails_thenThrowCryptoException() throws Exception {
        var verificationData = TestDataFactory.verificationData();

        doThrow(InvalidPublicKeyException.class).when(devicePublicKeyService).decodePublicKey(any());

        assertThatThrownBy(() -> registrationCryptoService.verifyAngExtractPublicKeyBytes(verificationData))
            .isInstanceOf(CryptoException.class).hasCauseInstanceOf(InvalidPublicKeyException.class);
    }

    @Test
    void whenCreatePublicKeyFails_thenThrowCryptoException() throws Exception {
        byte[] publicKeyBytes = new byte[44];
        var verificationData = TestDataFactory.verificationData();

        when(devicePublicKeyService.decodePublicKey(any())).thenReturn(publicKeyBytes);
        doThrow(InvalidPublicKeyException.class).when(devicePublicKeyService).createPublicKey(any());

        assertThatThrownBy(() -> registrationCryptoService.verifyAngExtractPublicKeyBytes(verificationData))
            .isInstanceOf(CryptoException.class).hasCauseInstanceOf(InvalidPublicKeyException.class);
    }

    @Test
    void whenBreakVerification_thenThrowCryptoException() throws Exception {
        var verificationData = TestDataFactory.verificationData();
        byte[] publicKeyBytes = new byte[44];

        when(devicePublicKeyService.decodePublicKey(any())).thenReturn(publicKeyBytes);
        when(devicePublicKeyService.createPublicKey(any())).thenReturn(mock(PublicKey.class));
        when(signatureVerifier.verify(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> registrationCryptoService.verifyAngExtractPublicKeyBytes(verificationData))
            .isInstanceOf(CryptoException.class);
    }

    @Test
    void shouldReturnPublicKeyBytes() throws Exception {
        var verificationData = TestDataFactory.verificationData();
        byte[] publicKeyBytes = new byte[44];
        PublicKey publicKey = mock(PublicKey.class);

        when(devicePublicKeyService.decodePublicKey(any())).thenReturn(publicKeyBytes);
        when(devicePublicKeyService.createPublicKey(any())).thenReturn(publicKey);
        when(signatureVerifier.verify(any(), any(), any())).thenReturn(true);

        assertThat(registrationCryptoService.verifyAngExtractPublicKeyBytes(verificationData))
            .isEqualTo(publicKeyBytes);

        verify(devicePublicKeyService).decodePublicKey(eq(verificationData.base64PublicKey()));
        verify(devicePublicKeyService).createPublicKey(argThat(bytes -> Arrays.equals(bytes, publicKeyBytes)));
        verify(signatureVerifier).verify(eq(publicKey), any(byte[].class), any(byte[].class));
    }

    @Test
    void whenSignatureIsInvalidBase64_thenThrowCryptoException() throws Exception {
        var verificationData = TestDataFactory.verificationData();
        var data = new DeviceRegistrationVerificationData(
            verificationData.deviceName(),
            verificationData.deviceType(),
            verificationData.base64PublicKey(),
            verificationData.inviteToken(),
            "%%%invalid%%%"
        );

        when(devicePublicKeyService.decodePublicKey(any()))
            .thenReturn(new byte[44]);
        when(devicePublicKeyService.createPublicKey(any()))
            .thenReturn(mock(PublicKey.class));

        assertThatThrownBy(() ->
            registrationCryptoService.verifyAngExtractPublicKeyBytes(data)
        ).isInstanceOf(CryptoException.class)
            .hasMessageContaining("Invalid signature");
    }

    private static class TestDataFactory {
        static String base64PublicKey() throws NoSuchAlgorithmException {
            return Base64.getEncoder().encodeToString(
                KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded()
            );
        }

        static DeviceRegistrationVerificationData verificationData() throws NoSuchAlgorithmException {
            return new DeviceRegistrationVerificationData(
                "test device",
                DeviceType.MOBILE,
                base64PublicKey(),
                UUID.randomUUID(),
                Base64.getEncoder().encodeToString("base64Signature".getBytes())
            );
        }
    }
}
