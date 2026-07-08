package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.request.common.SignedAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
@RequiredArgsConstructor
public class SignatureVerifier {
    private final KeySignatureService keySignatureService;

    void verifySignature(AuthPipelineContext<? extends SignedAuthRequest> context) {
        try {
            keySignatureService.verify(
                context.getAuthData().deviceAuthData().publicKey(),
                context.getRequest().payload(),
                Base64.getDecoder().decode(context.getRequest().base64Signature())
            );
        } catch (IllegalArgumentException e) {
            throw AuthException.invalidCryptographyData(
                "Invalid base64 signature.", e
            );
        } catch (CryptoException e) {
            throw AuthException.signatureVerificationFailed(
                "Signature verification failed.", e
            );
        }
    }
}
