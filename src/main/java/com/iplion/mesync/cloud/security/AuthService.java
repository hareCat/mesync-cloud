package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.auth.AuthPipelineContext;
import com.iplion.mesync.cloud.security.auth.AuthRequest;
import com.iplion.mesync.cloud.security.auth.DeviceAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

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

    public RegistrationAuthResult verifyRegistrationRequest(RegistrationAuthRequest request) {
        var context = runPipeline(request, List.of(
            this::registrationAuthRedisCheck,
            this::createPublicKey,
            this::verifySignature
        ));

        return new RegistrationAuthResult(
            context.getJwtUserData(),
            context.getPublicKey()
        );
    }

    public <T extends DeviceAuthRequest> AuthData verifyDeviceManagerRequest(T request) {
        var context = runPipeline(request, List.of(
            this::deviceAuthRedisCheck,
            this::getDeviceAuthData,
            this::deviceOwnerCheck,
            this::verifySignature
        ));

        return context.getAuthData();
    }

    public <T extends DeviceAuthRequest> AuthData verifyMessagingRequest(T request) {
        var context = runPipeline(request, List.of(
            this::deviceAuthRedisCheck,
            this::getDeviceAuthData,
            this::deviceOwnerCheck,
            this::deviceTypeCheck,
            this::verifySignature
        ));

        return context.getAuthData();
    }

    private <T extends AuthRequest> AuthPipelineContext<T> runPipeline(
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

    private <T extends DeviceAuthRequest> void getDeviceAuthData(AuthPipelineContext<T> context) {
        AuthData authData;
        try {
            authData = authContextService.getAuthContext(
                context.getJwtUserData().authId(),
                context.getRequest().devicePublicId()
            );
        } catch (DeviceException e) {
            throw AuthException.deviceNotFound(context.getJwtUserData().authId(), e);
        }

        SecurityContextUtils.setAuthData(authData);

        context.setSecuritySubjectId(authData.deviceAuthData().publicId());
        context.setAuthData(authData);
        context.setPublicKey(authData.deviceAuthData().publicKey());

    }

    private void deviceTypeCheck(AuthPipelineContext<? extends DeviceAuthRequest> context) {
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

    private void deviceOwnerCheck(AuthPipelineContext<? extends DeviceAuthRequest> context) {
        UUID jwtAuthId = context.getJwtUserData().authId();
        UUID dbAuthId = context.getAuthData().userAuthData().authId();
        if (!dbAuthId.equals(jwtAuthId)) {
            throw AuthException.deviceOwnershipMismatch(
                jwtAuthId,
                dbAuthId
            );
        }
    }

    private void registrationAuthRedisCheck(AuthPipelineContext<RegistrationAuthRequest> context) {
        var registrationProperties = appProperties.registration();

        redisCheck(context.getJwtUserData().authId(), subjectId -> redisSecurityStore.registrationSecurityCheck(
            RedisKeys.registrationNonceKey(subjectId, context.getRequest().nonce()),
            RedisKeys.registrationRateLimitKey(subjectId),
            registrationProperties.nonceTtl(),
            registrationProperties.rateLimitTtl(),
            registrationProperties.attempts()
        ));
    }

    private void deviceAuthRedisCheck(AuthPipelineContext<? extends DeviceAuthRequest> context) {
        var authProperties = appProperties.auth();

        redisCheck(context.getRequest().devicePublicId(),
            subjectId -> redisSecurityStore.deviceAuthSecurityCheck(
                RedisKeys.authDeviceRevokedKey(subjectId),
                RedisKeys.authNonceKey(subjectId, context.getRequest().nonce()),
                RedisKeys.authRateLimitKey(subjectId),
                authProperties.nonceTtl(),
                authProperties.rateLimitTtl(),
                authProperties.attempts()
            ));
    }

    private void redisCheck(UUID id, Consumer<UUID> checker) {
        try {
            checker.accept(id);
        } catch (RedisOperationException e) {
            throw AuthException.redisOperationError(id, e);
        }
    }

    private void createPublicKey(AuthPipelineContext<RegistrationAuthRequest> context) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(context.getRequest().base64PublicKey());
            context.setPublicKey(keySignatureService.createPublicKey(publicKeyBytes));
        } catch (IllegalArgumentException e) {
            throw AuthException.cryptographyFailed(
                "Invalid base64 publicKey. subjectId: " + context.getSecuritySubjectId(), e
            );
        } catch (InvalidPublicKeyException e) {
            throw AuthException.cryptographyFailed(
                "Invalid public key. subjectId: " + context.getSecuritySubjectId(), e
            );
        }
    }

    private void verifySignature(AuthPipelineContext<? extends AuthRequest> context) {
        try {
            keySignatureService.verify(
                context.getPublicKey(),
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

}
