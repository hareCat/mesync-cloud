package com.iplion.mesync.cloud.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.api.DeviceNotFoundException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.AuthDataProjection;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class AuthContextServiceTest extends BaseUnitTest {
    @Mock
    Cache<UUID, UserAuthData> userAuthCache;
    @Mock
    Cache<UUID, DeviceAuthData> deviceAuthCache;
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserRepository userRepository;
    @Mock
    KeySignatureService keySignatureService;

    private AuthContextService authContextService;

    @BeforeEach
    void setUp() {
        authContextService = new AuthContextService(
            deviceAuthCache,
            userAuthCache,
            userRepository,
            deviceRepository,
            keySignatureService
        );
    }

    @Test
    public void getAuthContext_shouldReturnAuthContext_whenUserAndDeviceAreInCache() throws Exception {
        var authData = TestModelFactory.authData();
        UUID userAuthId = authData.userAuthData().authId();
        UUID devicePublicId = authData.deviceAuthData().publicId();

        when(userAuthCache.getIfPresent(any())).thenReturn(authData.userAuthData());
        when(deviceAuthCache.getIfPresent(any())).thenReturn(authData.deviceAuthData());

        AuthData result = authContextService.getFullAuthContext(devicePublicId);

        verify(userAuthCache).getIfPresent(eq(userAuthId));
        verify(deviceAuthCache).getIfPresent(eq(devicePublicId));
        verifyNoInteractions(deviceRepository);
        verify(userAuthCache, never()).put(any(), any());
        verify(deviceAuthCache, never()).put(any(), any());

        assertThat(result.userAuthData().authId()).isEqualTo(userAuthId);
        assertThat(result.deviceAuthData().publicId()).isEqualTo(devicePublicId);
    }

    @Test
    public void getAuthContext_shouldLoadFromRepositoryAndUpdateCaches_whenDeviceNotInCache() throws Exception {
        var authData = TestModelFactory.authData();
        UUID userAuthId = authData.userAuthData().authId();
        UUID devicePublicId = authData.deviceAuthData().publicId();
        var authDataProjection = mock(AuthDataProjection.class);

        when(deviceAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceRepository.findAuthContextByPublicId(any())).thenReturn(Optional.of(authDataProjection));
        when(authDataProjection.toAuthData(any())).thenReturn(authData);

        AuthData result = authContextService.getFullAuthContext(devicePublicId);

        verify(deviceAuthCache).getIfPresent(eq(devicePublicId));
        verify(deviceRepository).findAuthContextByPublicId(eq(devicePublicId));
        verify(userAuthCache).put(eq(userAuthId), eq(authData.userAuthData()));
        verify(deviceAuthCache).put(eq(devicePublicId), eq(authData.deviceAuthData()));

        assertThat(result.userAuthData().authId()).isEqualTo(userAuthId);
        assertThat(result.deviceAuthData().publicId()).isEqualTo(devicePublicId);
    }

    @Test
    public void getAuthContext_shouldThrow_whenDeviceNotFound() throws Exception {
        var authData = TestModelFactory.authData();
        UUID devicePublicId = authData.deviceAuthData().publicId();

        when(deviceAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceRepository.findAuthContextByPublicId(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authContextService.getFullAuthContext(devicePublicId))
            .isInstanceOf(DeviceNotFoundException.class)
            .hasMessageContaining("found");

        verify(userAuthCache, never()).put(any(), any());
        verify(deviceAuthCache, never()).put(any(), any());
    }

    @Test
    public void findUserAuthContext_shouldReturnCachedUser_whenUserInCache() {
        UserAuthData userAuthData = TestModelFactory.userAuthData();

        when(userAuthCache.getIfPresent(any())).thenReturn(userAuthData);

        Optional<UserAuthData> result = authContextService.findUserAuthContext(userAuthData.authId());

        assertThat(result).contains(userAuthData);
        verify(userAuthCache).getIfPresent(eq(userAuthData.authId()));
        verifyNoInteractions(userRepository);
    }

    @Test
    public void findUserAuthContext_shouldLoadFromRepositoryAndUpdateCache_whenUserNotInCache() {
        UserAuthData userAuthData = TestModelFactory.userAuthData();
        User user = new User();
        user.setId(userAuthData.id());
        user.setAuthId(userAuthData.authId());
        user.setKeyVersion(userAuthData.keyVersion());

        when(userAuthCache.getIfPresent(any())).thenReturn(null);
        when(userRepository.findByAuthId(any())).thenReturn(Optional.of(user));

        Optional<UserAuthData> result = authContextService.findUserAuthContext(userAuthData.authId());

        assertThat(result).contains(userAuthData);
        verify(userAuthCache).put(eq(userAuthData.authId()), eq(userAuthData));
    }

    @Test
    public void findUserAuthContext_shouldReturnEmpty_whenUserNotFound() {
        UUID userAuthId = UUID.randomUUID();

        when(userAuthCache.getIfPresent(any())).thenReturn(null);
        when(userRepository.findByAuthId(any())).thenReturn(Optional.empty());

        Optional<UserAuthData> result = authContextService.findUserAuthContext(userAuthId);

        assertThat(result).isEmpty();
        verify(userAuthCache, never()).put(any(), any());
    }

}
