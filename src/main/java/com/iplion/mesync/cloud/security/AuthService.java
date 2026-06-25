package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.error.api.UserNotFoundException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.auth.AuthPipelineContext;
import com.iplion.mesync.cloud.security.auth.SignedAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.auth.UnregisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

// TODO check request lastMessageId with saved device lastMessageId from caffeine
@Service
@RequiredArgsConstructor
public class AuthService {
    private final RedisSecurityStore redisSecurityStore;
    private final KeySignatureService keySignatureService;
    private final AuthContextService authContextService;

    private final AppProperties appProperties;

    public <T extends UnregisteredDeviceAuthRequest> JwtUserData verifyUnregisteredDeviceRequest(T request) {
        var context = runPipeline(request, List.of(
            this::unregisteredDeviceAuthRedisCheck,
            this::getUnregisteredDeviceAuthData,
            this::verifySignature
        ));

        return context.getJwtUserData();
    }

    public <T extends RegisteredDeviceAuthRequest> void verifyDeviceManagerRequest(T request) {
        runPipeline(request, List.of(
            this::registeredDeviceAuthRedisCheck,
            this::getRegisteredDeviceAuthData,
            this::deviceOwnerCheck,
            this::verifySignature
        ));
    }

    public <T extends RegisteredDeviceAuthRequest> void verifyMessagingRequest(T request) {
        runPipeline(request, List.of(
            this::registeredDeviceAuthRedisCheck,
            this::getRegisteredDeviceAuthData,
            this::deviceOwnerCheck,
            this::deviceTypeCheck,
            this::verifySignature
        ));
    }

    private <T extends SignedAuthRequest> AuthPipelineContext<T> runPipeline(
        T request,
        Iterable<Consumer<AuthPipelineContext<T>>> steps
    ) {
        AuthPipelineContext<T> context = new AuthPipelineContext<>(request);

        try {
            JwtUserData jwtUserData = JwtUtils.extractUserData(SecurityContextUtils.getJwt());
            context.setJwtUserData(jwtUserData);
            context.setSecuritySubjectId(jwtUserData.authId());
        } catch (InvalidTokenException e) {
            throw AuthException.wrongRequestData("Wrong JWT token.", e);
        }

        for (Consumer<AuthPipelineContext<T>> step : steps) {
            step.accept(context);
        }

        return context;
    }

    private <T extends RegisteredDeviceAuthRequest> void getRegisteredDeviceAuthData(AuthPipelineContext<T> context) {
        AuthData authData = authContextService.getFullAuthContext(
            context.getJwtUserData().authId(),
            context.getRequest().devicePublicId()
        );

        SecurityContextUtils.setAuthData(authData);

        context.setSecuritySubjectId(authData.deviceAuthData().publicId());
        context.setAuthData(authData);
    }

    private <T extends UnregisteredDeviceAuthRequest> void getUnregisteredDeviceAuthData(AuthPipelineContext<T> context) {
        UserAuthData userAuthData;
        try {
            userAuthData = authContextService.getUserAuthContext(context.getJwtUserData().authId());
        } catch (UserNotFoundException e) {
            userAuthData = new UserAuthData(
                null,
                context.getJwtUserData().authId(),
                null
            );
        }

        DeviceAuthData deviceAuthData = new DeviceAuthData(
            null,
            null,
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

    private void deviceTypeCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        DeviceType jwtDeviceType = DeviceType.fromClientId(context.getJwtUserData().clientId());
        AuthData authData = context.getAuthData();
        if (!jwtDeviceType.equals(authData.deviceAuthData().deviceType())) {
            throw AuthException.deviceTypeMismatch(
                authData.userAuthData().authId(),
                authData.deviceAuthData().publicId(),
                jwtDeviceType,
                authData.deviceAuthData().deviceType()
            );
        }
    }

    private void deviceOwnerCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        UUID jwtAuthId = context.getJwtUserData().authId();
        UUID dbAuthId = context.getAuthData().userAuthData().authId();
        if (!dbAuthId.equals(jwtAuthId)) {
            throw AuthException.deviceOwnershipMismatch(
                jwtAuthId,
                dbAuthId
            );
        }
    }

    private void unregisteredDeviceAuthRedisCheck(AuthPipelineContext<? extends UnregisteredDeviceAuthRequest> context) {
        var registrationProperties = appProperties.registration();

        UUID subjectId = context.getJwtUserData().authId();

        redisSecurityStore.registrationSecurityCheck(
            RedisKeys.registrationNonceKey(subjectId, context.getRequest().nonce()),
            RedisKeys.registrationRateLimitKey(subjectId),
            registrationProperties.nonceTtl(),
            registrationProperties.rateLimitTtl(),
            registrationProperties.attempts()
        );
    }

    private void registeredDeviceAuthRedisCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        var authProperties = appProperties.auth();

        UUID subjectId = context.getRequest().devicePublicId();
        redisSecurityStore.deviceAuthSecurityCheck(
            RedisKeys.authDeviceRevokedKey(subjectId),
            RedisKeys.authNonceKey(subjectId, context.getRequest().nonce()),
            RedisKeys.authRateLimitKey(subjectId),
            authProperties.nonceTtl(),
            authProperties.rateLimitTtl(),
            authProperties.attempts()
        );
    }

    private void verifySignature(AuthPipelineContext<? extends SignedAuthRequest> context) {
        try {
            keySignatureService.verify(
                context.getAuthData().deviceAuthData().publicKey(),
                context.getRequest().payload(),
                Base64.getDecoder().decode(context.getRequest().base64Signature())
            );
        } catch (IllegalArgumentException e) {
            throw AuthException.cryptographyFailed(
                "Invalid base64 signature. subjectId: " + context.getSecuritySubjectId(), e
            );
        } catch (CryptoException e) {
            throw AuthException.cryptographyFailed(
                "Signature verification failed. subjectId: " + context.getSecuritySubjectId(), e
            );
        }
    }

    private PublicKey createPublicKey(String base64SigningPublicKey) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64SigningPublicKey);
            return keySignatureService.createPublicKey(publicKeyBytes);
        } catch (IllegalArgumentException e) {
            throw AuthException.cryptographyFailed(
                "Invalid base64 publicKey.", e
            );
        } catch (InvalidPublicKeyException e) {
            throw AuthException.cryptographyFailed(
                "Invalid public key.", e
            );
        }
    }

}
