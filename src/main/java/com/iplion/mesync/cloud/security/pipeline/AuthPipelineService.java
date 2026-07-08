package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.request.RegisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.request.SignedAuthRequest;
import com.iplion.mesync.cloud.security.request.UnregisteredDeviceAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Consumer;

// TODO check request lastMessageId with saved device lastMessageId from caffeine
@Service
@RequiredArgsConstructor
public class AuthPipelineService {
    private final RedisAuthChecker redisAuthChecker;
    private final DeviceAuthChecker deviceAuthChecker;
    private final AuthDataLoader authDataLoader;
    private final SignatureVerifier signatureVerifier;

    public <T extends UnregisteredDeviceAuthRequest> AuthPipelineResult verifyUnregisteredDeviceRequest(T request) {
        var context = runPipeline(request, List.of(
            redisAuthChecker::unregisteredDeviceSecurityCheck,
            authDataLoader::loadUnregisteredDeviceAuthData,
            signatureVerifier::verifySignature
        ));

        return new AuthPipelineResult(
            context.getAuthData(),
            context.getJwtUserData()
        );
    }

    public <T extends RegisteredDeviceAuthRequest> AuthData verifyDeviceManagerRequest(T request) {
        return runPipeline(request, List.of(
            redisAuthChecker::registeredDeviceSecurityCheck,
            authDataLoader::loadRegisteredDeviceAuthData,
            deviceAuthChecker::deviceOwnerCheck,
            signatureVerifier::verifySignature
        )).getAuthData();
    }

    public <T extends RegisteredDeviceAuthRequest> AuthData verifyMessagingRequest(T request) {
        return runPipeline(request, List.of(
            redisAuthChecker::registeredDeviceSecurityCheck,
            authDataLoader::loadRegisteredDeviceAuthData,
            deviceAuthChecker::deviceOwnerCheck,
            deviceAuthChecker::deviceTypeCheck,
            signatureVerifier::verifySignature
        )).getAuthData();
    }

    private <T extends SignedAuthRequest> AuthPipelineContext<T> runPipeline(
        T request,
        Iterable<Consumer<AuthPipelineContext<T>>> steps
    ) {
        AuthPipelineContext<T> context = new AuthPipelineContext<>(request);

        authDataLoader.loadJwtData(context);

        for (Consumer<AuthPipelineContext<T>> step : steps) {
            step.accept(context);
        }

        return context;
    }

}
