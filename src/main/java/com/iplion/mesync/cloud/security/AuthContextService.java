package com.iplion.mesync.cloud.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.error.api.DeviceNotFoundException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthContextService {
    private final Cache<UUID, DeviceAuthData> deviceAuthCache;
    private final Cache<UUID, UserAuthData> userAuthCache;
    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final KeySignatureService keySignatureService;

    public AuthData getFullAuthContext(UUID devicePublicId) {
        DeviceAuthData deviceAuthData = deviceAuthCache.getIfPresent(devicePublicId);

        if (deviceAuthData == null) {
            AuthData authData = deviceRepository.findAuthContextByPublicId(devicePublicId)
                .map(projection -> projection.toAuthData(keySignatureService))
                .orElseThrow(() -> new DeviceNotFoundException("Device not found. devicePublicId: " + devicePublicId));

            userAuthCache.put(authData.userAuthData().authId(), authData.userAuthData());
            deviceAuthCache.put(devicePublicId, authData.deviceAuthData());

            return authData;
        }

        UUID userAuthId = deviceAuthData.ownerAuthId();

        UserAuthData userAuthData = findUserAuthContext(userAuthId)
            .orElseThrow(() -> AuthException.userNotFound(userAuthId));

        return new AuthData(userAuthData, deviceAuthData);
    }

    public Optional<UserAuthData> findUserAuthContext(UUID userAuthId) {
        UserAuthData userAuthData = userAuthCache.getIfPresent(userAuthId);

        if (userAuthData != null) {
            return Optional.of(userAuthData);
        }

        return userRepository.findByAuthId(userAuthId)
            .map(user -> {
                UserAuthData foundUserAuthData = UserAuthData.from(user);
                userAuthCache.put(user.getAuthId(), foundUserAuthData);
                return foundUserAuthData;
            });
    }

}
