package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.model.DeviceRegistrationPayload;
import com.iplion.mesync.cloud.model.DeviceRegistrationVerificationData;
import com.iplion.mesync.cloud.security.crypto.DeviceRegistrationSignaturePayloadBuilder;
import com.iplion.mesync.cloud.security.crypto.SignatureVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RegistrationCryptoService {
    private final SignatureVerifier signatureVerifier;
    private final DevicePublicKeyService devicePublicKeyService;

    public byte[] verifyAngExtractPublicKeyBytes(DeviceRegistrationVerificationData data) {
        byte[] payload = DeviceRegistrationSignaturePayloadBuilder.build(new DeviceRegistrationPayload(
            data.deviceName(),
            data.deviceType(),
            data.base64PublicKey(),
            data.inviteToken()
        ));

        byte[] decodedPublicKey;
        PublicKey publicKey;
        try {
            decodedPublicKey = devicePublicKeyService.decodePublicKey(data.base64PublicKey());
            publicKey = devicePublicKeyService.createPublicKey(decodedPublicKey);
        } catch (InvalidPublicKeyException e) {
            throw new CryptoException("Invalid public key format", e);
        }

        if (!signatureVerifier.verify(
            publicKey,
            payload,
            decodedSignature(data.base64Signature())
        )) {
            throw new CryptoException("Signature verification failed");
        }

        return decodedPublicKey;
    }

    private byte[] decodedSignature(String base64Signature) {
        try {
            return Base64.getDecoder().decode(base64Signature);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid signature", e);
        }
    }
}
