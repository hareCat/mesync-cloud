package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.request.RegisteredDeviceAuthRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.http.HttpStatus;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

class SignatureVerifierTest extends BaseUnitTest {
    @Mock
    KeySignatureService keySignatureService;

    SignatureVerifier signatureVerifier;

    @BeforeEach
    void setUp() {
        signatureVerifier = new SignatureVerifier(keySignatureService);
    }

    @Test
    void verifySignature_shouldVerifySignature_whenRequestValid() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        byte[] payload = "test-payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = new byte[64];
        var authPipelineContext = registeredAuthPipelineContext(
            testContext,
            payload,
            Base64.getEncoder().encodeToString(signature)
        );

        signatureVerifier.verifySignature(authPipelineContext);

        verify(keySignatureService).verify(eq(testContext.publicKey()), eq(payload), eq(signature));
    }

    @Test
    void verifySignature_shouldThrowBadRequest_whenBase64SignatureInvalid() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = registeredAuthPipelineContext(
            testContext,
            "test-payload".getBytes(StandardCharsets.UTF_8),
            "invalid base64 !"
        );

        assertThatThrownBy(() -> signatureVerifier.verifySignature(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("Invalid base64 signature");
            });
    }

    @Test
    void verifySignature_shouldThrowForbidden_whenSignatureVerificationFails() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        byte[] payload = "test-payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = new byte[64];
        var authPipelineContext = registeredAuthPipelineContext(
            testContext,
            payload,
            Base64.getEncoder().encodeToString(signature)
        );

        doThrow(new CryptoException("bad signature")).when(keySignatureService).verify(any(), any(), any());

        assertThatThrownBy(() -> signatureVerifier.verifySignature(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains("Signature verification failed");
                assertThat(e.getClientMessage()).isEqualTo("Unable to verify your device.");
            });
    }

    private AuthPipelineContext<RegisteredDeviceAuthRequest> registeredAuthPipelineContext(
        TestPipelineFactory.TestContext testContext,
        byte[] payload,
        String base64Signature
    ) {
        AuthPipelineContext<RegisteredDeviceAuthRequest> authPipelineContext = new AuthPipelineContext<>(
            new TestPipelineFactory.TestRegisteredDeviceAuthRequest(
                base64Signature,
                testContext.nonce(),
                testContext.devicePublicId(),
                payload
            )
        );
        authPipelineContext.setAuthData(testContext.authData());
        return authPipelineContext;
    }

}
