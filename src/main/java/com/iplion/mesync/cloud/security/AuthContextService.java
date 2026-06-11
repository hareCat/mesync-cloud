package com.iplion.mesync.cloud.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthContextService {
    private final Cache<UUID, DeviceAuthData> deviceAuthCache;
    private final Cache<UUID, UserAuthData> userAuthCache;
    private final DeviceRepository deviceRepository;
    private final KeySignatureService keySignatureService;

    public AuthData getAuthContext(UUID userAuthId, UUID devicePublicId) {
        UserAuthData userAuthData = userAuthCache.getIfPresent(userAuthId);
        DeviceAuthData deviceAuthData = deviceAuthCache.getIfPresent(devicePublicId);

        if (userAuthData == null || deviceAuthData == null) {
            AuthData authData = deviceRepository.findAuthContextByPublicId(devicePublicId)
                .map(projection -> projection.toAuthContext(keySignatureService))
                .orElseThrow(() -> new DeviceException("Device not found. devicePublicId: " + devicePublicId));

            userAuthCache.put(authData.userAuthData().authId(), authData.userAuthData());
            deviceAuthCache.put(devicePublicId, authData.deviceAuthData());

            return authData;
        }

        return new AuthData(userAuthData, deviceAuthData);
    }

}
