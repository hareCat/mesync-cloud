package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.logging.MdcUtils;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.AuthContextService;
import com.iplion.mesync.cloud.security.JwtUtils;
import com.iplion.mesync.cloud.security.SecurityContextUtils;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.request.RegisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.request.SignedAuthRequest;
import com.iplion.mesync.cloud.security.request.UnregisteredDeviceAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class AuthDataLoader {
    private final AuthContextService authContextService;
    private final KeySignatureService keySignatureService;

    <T extends SignedAuthRequest> void loadJwtData(AuthPipelineContext<T> context) {
        try {
            JwtUserData jwtUserData = JwtUtils.extractUserData(SecurityContextUtils.getJwt());
            context.setJwtUserData(jwtUserData);
            MdcUtils.putJwtUserData(jwtUserData);
        } catch (InvalidTokenException e) {
            throw AuthException.wrongRequestData("Wrong JWT token.", e);
        }
    }

    <T extends RegisteredDeviceAuthRequest> void loadRegisteredDeviceAuthData(AuthPipelineContext<T> context) {
        AuthData authData = authContextService.getFullAuthContext(context.getRequest().devicePublicId());

        SecurityContextUtils.setAuthData(authData);

        context.setAuthData(authData);
    }

    <T extends UnregisteredDeviceAuthRequest> void loadUnregisteredDeviceAuthData(AuthPipelineContext<T> context) {
        UUID userAuthId = context.getJwtUserData().authId();

        UserAuthData userAuthData = authContextService.findUserAuthContext(userAuthId)
            .orElseGet(() -> new UserAuthData(
                null,
                userAuthId,
                null
            ));

        DeviceAuthData deviceAuthData = new DeviceAuthData(
            null,
            null,
            userAuthId,
            DeviceType.fromClientId(context.getJwtUserData().clientId()),
            createPublicKey(context.getRequest().base64SigningPublicKey())
        );

        AuthData authData = new AuthData(
            userAuthData,
            deviceAuthData
        );

        SecurityContextUtils.setAuthData(authData);

        context.setAuthData(authData);
    }

    PublicKey createPublicKey(String base64SigningPublicKey) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64SigningPublicKey);
            return keySignatureService.createPublicKey(publicKeyBytes);
        } catch (IllegalArgumentException e) {
            throw AuthException.invalidCryptographyData(
                "Invalid base64 publicKey.", e
            );
        } catch (InvalidPublicKeyException e) {
            throw AuthException.invalidCryptographyData(
                "Invalid public key.", e
            );
        }
    }

}
