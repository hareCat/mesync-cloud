package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.model.DeviceRegistrationPayload;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.crypto.DeviceRegistrationSignaturePayloadBuilder;
import com.iplion.mesync.cloud.security.crypto.SignatureVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SignatureVerificationService {
    private final SignatureVerifier signatureVerifier;

    public void deviceRegistrationVerify(
        PublicKey publicKey,
        String deviceName,
        DeviceType deviceType,
        String base64PublicKey,
        UUID inviteToken,
        String base64Signature
    ) {
        byte[] payload = DeviceRegistrationSignaturePayloadBuilder.build(new DeviceRegistrationPayload(
            deviceName,
            deviceType,
            base64PublicKey,
            inviteToken
        ));

        byte[] decodedSignature;

        try {
            decodedSignature = Base64.getDecoder().decode(base64Signature);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid signature");
        }

        if (!signatureVerifier.verify(
            publicKey,
            payload,
            decodedSignature
        )) {
            throw new CryptoException("Signature verification failed");
        }
    }
}
