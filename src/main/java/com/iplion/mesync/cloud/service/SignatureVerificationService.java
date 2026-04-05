package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.model.DeviceRegistrationPayload;
import com.iplion.mesync.cloud.model.DeviceRegistrationVerificationData;
import com.iplion.mesync.cloud.security.crypto.DeviceRegistrationSignaturePayloadBuilder;
import com.iplion.mesync.cloud.security.crypto.SignatureVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@RequiredArgsConstructor
public class SignatureVerificationService {
    private final SignatureVerifier signatureVerifier;

    public void deviceRegistrationVerify(DeviceRegistrationVerificationData data) {
        byte[] payload = DeviceRegistrationSignaturePayloadBuilder.build(new DeviceRegistrationPayload(
            data.deviceName(),
            data.deviceType(),
            data.base64PublicKey(),
            data.inviteToken()
        ));

        byte[] decodedSignature;

        try {
            decodedSignature = Base64.getDecoder().decode(data.base64Signature());
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid signature");
        }

        if (!signatureVerifier.verify(
            data.publicKey(),
            payload,
            decodedSignature
        )) {
            throw new CryptoException("Signature verification failed");
        }
    }
}
