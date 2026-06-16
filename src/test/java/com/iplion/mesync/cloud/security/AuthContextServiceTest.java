package com.iplion.mesync.cloud.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.repository.DeviceRepository;
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
    KeySignatureService keySignatureService;

    private AuthContextService authContextService;

    @BeforeEach
    void setUp() {
        authContextService = new AuthContextService(
            deviceAuthCache,
            userAuthCache,
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

        AuthData result = authContextService.getAuthContext(userAuthId, devicePublicId);

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

        when(userAuthCache.getIfPresent(any())).thenReturn(authData.userAuthData());
        when(deviceAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceRepository.findAuthContextByPublicId(any())).thenReturn(Optional.of(authDataProjection));
        when(authDataProjection.toAuthData(any())).thenReturn(authData);

        AuthData result = authContextService.getAuthContext(userAuthId, devicePublicId);

        verify(userAuthCache).getIfPresent(eq(userAuthId));
        verify(deviceAuthCache).getIfPresent(eq(devicePublicId));
        verify(deviceRepository).findAuthContextByPublicId(eq(devicePublicId));
        verify(userAuthCache).put(eq(userAuthId), eq(authData.userAuthData()));
        verify(deviceAuthCache).put(eq(devicePublicId), eq(authData.deviceAuthData()));

        assertThat(result.userAuthData().authId()).isEqualTo(userAuthId);
        assertThat(result.deviceAuthData().publicId()).isEqualTo(devicePublicId);
    }

    @Test
    public void getAuthContext_shouldLoadFromRepositoryAndUpdateCaches_whenUserNotInCache() throws Exception {
        var authData = TestModelFactory.authData();
        UUID userAuthId = authData.userAuthData().authId();
        UUID devicePublicId = authData.deviceAuthData().publicId();
        var authDataProjection = mock(AuthDataProjection.class);

        when(userAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceAuthCache.getIfPresent(any())).thenReturn(authData.deviceAuthData());
        when(deviceRepository.findAuthContextByPublicId(any())).thenReturn(Optional.of(authDataProjection));
        when(authDataProjection.toAuthData(any())).thenReturn(authData);

        AuthData result = authContextService.getAuthContext(userAuthId, devicePublicId);

        verify(userAuthCache).getIfPresent(eq(userAuthId));
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
        UUID userAuthId = authData.userAuthData().authId();
        UUID devicePublicId = authData.deviceAuthData().publicId();

        when(userAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceAuthCache.getIfPresent(any())).thenReturn(null);
        when(deviceRepository.findAuthContextByPublicId(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authContextService.getAuthContext(userAuthId, devicePublicId))
            .isInstanceOf(DeviceException.class)
            .hasMessageContaining("found");

        verify(userAuthCache, never()).put(any(), any());
        verify(deviceAuthCache, never()).put(any(), any());
    }

}
