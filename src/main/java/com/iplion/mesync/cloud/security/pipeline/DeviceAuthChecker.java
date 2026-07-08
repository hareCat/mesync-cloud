package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class DeviceAuthChecker {
    void deviceTypeCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        DeviceType jwtDeviceType = DeviceType.fromClientId(context.getJwtUserData().clientId());
        AuthData authData = context.getAuthData();
        if (!jwtDeviceType.equals(authData.deviceAuthData().deviceType())) {
            throw AuthException.deviceTypeMismatch(
                jwtDeviceType,
                authData.deviceAuthData().deviceType()
            );
        }
    }

    void deviceOwnerCheck(AuthPipelineContext<? extends RegisteredDeviceAuthRequest> context) {
        UUID jwtAuthId = context.getJwtUserData().authId();
        UUID deviceOwnerAuthId = context.getAuthData().deviceAuthData().ownerAuthId();

        if (!deviceOwnerAuthId.equals(jwtAuthId)) {
            throw AuthException.deviceOwnershipMismatch();
        }
    }

}
