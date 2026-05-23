package com.iplion.mesync.cloud.security;

import com.iplion.mesync.cloud.config.AuthProperties;
import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.error.AuthException;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.InvalidPublicKeyException;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.auth.AuthPipelineContext;
import com.iplion.mesync.cloud.security.auth.AuthRequest;
import com.iplion.mesync.cloud.security.auth.DeviceAuthRequest;
import com.iplion.mesync.cloud.security.auth.DeviceAuthResult;
import com.iplion.mesync.cloud.security.auth.PublicKeyAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.redis.RedisKeys;
import com.iplion.mesync.cloud.security.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.service.DeviceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

// TODO check request lastMessageId with saved device lastMessageId from caffeine
@Service
@RequiredArgsConstructor
public class SecurityService {
    private final RedisSecurityStore redisSecurityStore;
    private final KeySignatureService keySignatureService;
    private final DeviceService deviceService;

    private final RegistrationProperties registrationProperties;
    private final AuthProperties authProperties;

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

    public <T extends DeviceAuthRequest> DeviceAuthResult verifySaveInviteRequest(T request) {
        var context = runPipeline(request, List.of(
            this::deviceAuthRedisCheck,
            this::getDeviceAuthData,
            this::deviceOwnerCheck,
            this::verifySignature
        ));

        return new DeviceAuthResult(
            context.getJwtUserData(),
            context.getDeviceAuthData()
        );
    }

    public <T extends DeviceAuthRequest> DeviceAuthResult verifyMessagingRequest(T request) {
        var context = runPipeline(request, List.of(
            this::deviceAuthRedisCheck,
            this::getDeviceAuthData,
            this::deviceOwnerCheck,
            this::deviceTypeCheck,
            this::verifySignature
        ));

        return new DeviceAuthResult(
            context.getJwtUserData(),
            context.getDeviceAuthData()
        );
    }

    private <T extends AuthRequest> AuthPipelineContext<T> runPipeline(
        T request,
        Iterable<Consumer<AuthPipelineContext<T>>> steps
    ) {
        AuthPipelineContext<T> context = new AuthPipelineContext<>(request);

        try {
            JwtUserData jwtUserData = JwtUtils.extractUserData(request.jwt());
            context.setJwtUserData(jwtUserData);
            context.setSecuritySubjectId(jwtUserData.id());
        } catch (InvalidTokenException e) {
            throw AuthException.wrongRequestData("Wrong JWT token.", e);
        }

        for (Consumer<AuthPipelineContext<T>> step : steps) {
            step.accept(context);
        }

        return context;
    }

    private <T extends DeviceAuthRequest> void getDeviceAuthData(AuthPipelineContext<T> context) {
        UUID publicId = context.getRequest().publicId();
        DeviceAuthData deviceAuthData;
        try {
            deviceAuthData = deviceService.getDeviceAuthData(publicId);
        } catch (DeviceException e) {
            throw AuthException.deviceNotFound(context.getJwtUserData().id(), e);
        }

        context.setSecuritySubjectId(deviceAuthData.publicId());
        context.setDeviceAuthData(deviceAuthData);
        context.setPublicKey(deviceAuthData.publicKey());

    }

    private <T extends DeviceAuthRequest> void deviceTypeCheck(AuthPipelineContext<T> context) {
        DeviceType jwtDeviceType = DeviceType.fromClientId(context.getJwtUserData().clientId());
        DeviceAuthData deviceAuthData = context.getDeviceAuthData();
        if (!jwtDeviceType.equals(deviceAuthData.deviceType())) {
            throw AuthException.deviceTypeMismatch(
                deviceAuthData.userAuthId(),
                deviceAuthData.publicId(),
                jwtDeviceType,
                deviceAuthData.deviceType()
            );
        }
    }

    private <T extends DeviceAuthRequest> void deviceOwnerCheck(AuthPipelineContext<T> context) {
        UUID jwtAuthId = context.getJwtUserData().id();
        UUID dbAuthId = context.getDeviceAuthData().userAuthId();
        if (!dbAuthId.equals(jwtAuthId)) {
            throw AuthException.deviceOwnershipMismatch(
                jwtAuthId,
                dbAuthId
            );
        }
    }

    private <T extends AuthRequest> void registrationAuthRedisCheck(AuthPipelineContext<T> context) {
        redisCheck(context.getJwtUserData().id(), subjectId -> redisSecurityStore.registrationSecurityCheck(
            RedisKeys.registrationNonceKey(subjectId),
            RedisKeys.registrationRateLimitKey(subjectId),
            registrationProperties.nonceTtl(),
            registrationProperties.rateLimitTtl(),
            registrationProperties.attempts()
        ));
    }

    private <T extends DeviceAuthRequest> void deviceAuthRedisCheck(AuthPipelineContext<T> context) {
        redisCheck(context.getRequest().publicId(),
            subjectId -> redisSecurityStore.deviceAuthSecurityCheck(
                RedisKeys.authDeviceRevokedKey(subjectId),
                RedisKeys.authNonceKey(subjectId),
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

    private <T extends PublicKeyAuthRequest> void createPublicKey(AuthPipelineContext<T> context) {
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

    private <T extends AuthRequest> void verifySignature(AuthPipelineContext<T> context) {
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
