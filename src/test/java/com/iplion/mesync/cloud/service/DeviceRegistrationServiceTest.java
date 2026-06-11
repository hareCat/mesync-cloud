package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.SaveInviteResponseDto;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.AuthService;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.auth.RegistrationAuthResult;
import com.iplion.mesync.cloud.security.auth.SaveInviteAuthRequest;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceRegistrationServiceTest {
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserService userService;
    @Mock
    InvitationService invitationService;
    @Mock
    DeviceService deviceService;
    @Mock
    AuthService authService;
    @Mock
    KeySignatureService keySignatureService;

    @InjectMocks
    DeviceRegistrationService deviceRegistrationService;

    @Test
    void saveInviteToken_shouldSaveToken() {
        Instant expiredAt = Instant.now();
        Jwt jwt = mock(Jwt.class);
        AuthData authData = authContext();

        var request = saveInviteRequestDto();

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authData);
        when(invitationService.createInvite(any(), any(), any(), anyInt(), any())).thenReturn(expiredAt);

        SaveInviteResponseDto response = deviceRegistrationService.saveInviteToken(jwt, request);

        ArgumentCaptor<SaveInviteAuthRequest> captor = ArgumentCaptor.forClass(SaveInviteAuthRequest.class);
        verify(authService).verifyDeviceManagerRequest(captor.capture());
        SaveInviteAuthRequest authRequestData = captor.getValue();

        verify(invitationService).createInvite(
            any(UUID.class),
            eq(request.inviteToken()),
            eq(request.encryptedMasterKey()),
            eq(request.keyVersion()),
            eq(request.deviceType())
        );

        assertThat(authRequestData.jwt()).isEqualTo(jwt);
        assertThat(authRequestData.devicePublicId()).isEqualTo(request.devicePublicId());
        assertThat(authRequestData.inviteToken()).isEqualTo(request.inviteToken());
        assertThat(authRequestData.nonce()).isEqualTo(request.nonce());
        assertThat(authRequestData.base64Signature()).isEqualTo(request.base64Signature());
        assertThat(authRequestData.encryptedMasterKey()).isEqualTo(request.encryptedMasterKey());
        assertThat(response).isNotNull();
        assertThat(response.expiresAt()).isEqualTo(expiredAt);
    }

    @Test
    void saveInviteToken_shouldThrow_whenDeviceMasterKeyVersionOutdated() {
        DeviceType deviceType = DeviceType.MOBILE;

        var request = new SaveInviteRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1,
            deviceType,
            UUID.randomUUID(),
            Base64.getEncoder().encodeToString(new byte[64])
        );

        when(authService.verifyDeviceManagerRequest(any())).thenReturn(authContext());

        assertThatThrownBy(() -> deviceRegistrationService.saveInviteToken(mock(Jwt.class), request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e ->
                assertThat(e.getMessage()).contains("key")
            );

        verify(invitationService, never()).createInvite(any(), any(), any(), anyInt(), any());
    }

    @Test
    void registerDevice_whenUserAlreadyHaveActiveDevice_shouldRegisterAnotherOne() {
        DeviceType deviceType = DeviceType.DESKTOP;
        Jwt jwt = mock(Jwt.class);

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));
        DeviceInviteData deviceInviteData = new DeviceInviteData(
            ctx.encryptedMasterKey(),
            1,
            deviceType
        );

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.consumeInviteAndGetEncryptedMasterKey(any(), any(), any()))
            .thenReturn(deviceInviteData);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        doNothing().when(deviceService).saveWithRetry(any());

        DeviceRegisterResponseDto response = deviceRegistrationService.registerDevice(jwt, request);

        ArgumentCaptor<RegistrationAuthRequest> captor = ArgumentCaptor.forClass(RegistrationAuthRequest.class);
        verify(authService).verifyRegistrationRequest(captor.capture());
        RegistrationAuthRequest authRequestData = captor.getValue();

        assertThat(authRequestData.jwt()).isEqualTo(jwt);
        assertThat(authRequestData.base64Signature()).isEqualTo(request.base64Signature());
        assertThat(authRequestData.nonce()).isEqualTo(request.nonce());
        assertThat(authRequestData.inviteToken()).isEqualTo(request.inviteToken());
        assertThat(authRequestData.base64PublicKey()).isEqualTo(request.base64PublicKey());
        assertThat(response.devicePublicId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(request.deviceName());
        assertThat(response.encryptedMasterKey()).isEqualTo(ctx.encryptedMasterKey());
        assertThat(response.keyVersion()).isEqualTo(ctx.user().getKeyVersion());
    }

    @Test
    void registerDevice_whenUserNotHaveActiveDevices_shouldCreateFirstMobileDevice() {
        DeviceType deviceType = DeviceType.MOBILE;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        doNothing().when(deviceService).saveWithRetry(any());

        DeviceRegisterResponseDto response = deviceRegistrationService.registerDevice(mock(Jwt.class), request);

        verifyNoInteractions(invitationService);

        assertThat(response.devicePublicId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(request.deviceName());
        assertThat(response.encryptedMasterKey()).isNull();
    }

    @Test
    void registerDevice_whenFirstDeviceTypeNotMobile_shouldThrow() {
        var ctx = createContext(DeviceType.BROWSER);
        var request = deviceRegistrationRequest();
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(false);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(mock(Jwt.class), request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("mobile");
            });

        verifyNoInteractions(invitationService);
    }

    @Test
    void registerDevice_whenRequestInviteTokenMissing_shouldThrow() {
        var ctx = createContext(DeviceType.MOBILE);
        var request = new DeviceRegisterRequestDto(
            "test device",
            "a".repeat(44),
            Map.of("platform", "android"),
            null,
            UUID.randomUUID(),
            "a".repeat(80)
        );
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(mock(Jwt.class), request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("invite");
            });

        verifyNoInteractions(invitationService);
    }

    @Test
    void registerDevice_whenUserSavingError_shouldThrow() {
        var ctx = createContext(DeviceType.MOBILE);
        var request = deviceRegistrationRequest();
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenThrow(IllegalStateException.class);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(mock(Jwt.class), request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                    assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                    assertThat(e.getMessage()).contains("user");
                    assertThat(e.getCause()).isInstanceOf(IllegalStateException.class);
                }
            );

        verifyNoInteractions(keySignatureService);
    }

    @Test
    void registerDevice_whenDeviceSavingError_shouldThrow() {
        var ctx = createContext(DeviceType.MOBILE);
        var request = deviceRegistrationRequest();
        var result = new RegistrationAuthResult(ctx.jwtUserData(), mock(PublicKey.class));

        when(authService.verifyRegistrationRequest(any())).thenReturn(result);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        doThrow(DeviceException.class).when(deviceService).saveWithRetry(any());

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(mock(Jwt.class), request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                    assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                    assertThat(e.getMessage()).contains("device");
                    assertThat(e.getCause()).isInstanceOf(DeviceException.class);
                }
            );

        verify(keySignatureService).extractPublicKeyBytes(any());
    }

    // --------------------- helpers ---------------------

    private record TestContext(
        User user,
        String encryptedMasterKey,
        JwtUserData jwtUserData
    ) {
    }

    private TestContext createContext(DeviceType deviceType) {
        UUID authId = UUID.randomUUID();
        String encryptedMasterKey = "encryptedMasterKey";
        String email = "test@mail.com";
        String clientId = deviceType.getClientId();
        JwtUserData jwtUserData = new JwtUserData(authId, clientId, email, true);

        User user = new User();
        user.setId(1L);
        user.setEmail(email);

        return new TestContext(user, encryptedMasterKey, jwtUserData);
    }

    DeviceRegisterRequestDto deviceRegistrationRequest() {
        return new DeviceRegisterRequestDto(
            "test device",
            "a".repeat(44),
            Map.of("platform", "android"),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    SaveInviteRequestDto saveInviteRequestDto() {
        return new SaveInviteRequestDto(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            2,
            DeviceType.MOBILE,
            UUID.randomUUID(),
            Base64.getEncoder().encodeToString(new byte[64])
        );
    }

    public AuthData authContext() {
        return new AuthData(
            new UserAuthData(
                1L, UUID.randomUUID(), 2
            ),
            new DeviceAuthData(
                1L,
                UUID.randomUUID(),
                DeviceType.MOBILE,
                mock(PublicKey.class)
            )
        );
    }
}
