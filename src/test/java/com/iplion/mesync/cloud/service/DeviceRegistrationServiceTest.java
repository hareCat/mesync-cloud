package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreInviteRequestDto;
import com.iplion.mesync.cloud.controller.dto.registration.StoreInviteResponseDto;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.DeviceException;
import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineResult;
import com.iplion.mesync.cloud.security.pipeline.AuthPipelineService;
import com.iplion.mesync.cloud.security.request.RegistrationAuthRequest;
import com.iplion.mesync.cloud.security.request.StoreInviteAuthRequest;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.service.support.DeviceService;
import com.iplion.mesync.cloud.service.support.InvitationService;
import com.iplion.mesync.cloud.service.support.UserService;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.HttpStatus;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DeviceRegistrationServiceTest extends BaseUnitTest {
    @Mock
    DeviceRepository deviceRepository;
    @Mock
    UserService userService;
    @Mock
    InvitationService invitationService;
    @Mock
    DeviceService deviceService;
    @Mock
    AuthPipelineService authPipelineService;
    @Mock
    KeySignatureService keySignatureService;

    @InjectMocks
    DeviceRegistrationService deviceRegistrationService;

    @Test
    void storeInviteToken_shouldSaveToken() throws Exception {
        Instant expiredAt = Instant.now();
        var request = storeInviteRequestDto();

        when(authPipelineService.verifyDeviceManagerRequest(any())).thenReturn(TestModelFactory.authData());
        when(invitationService.createInvite(any(), any(), any())).thenReturn(expiredAt);

        StoreInviteResponseDto response = deviceRegistrationService.storeInviteToken(request);

        ArgumentCaptor<StoreInviteAuthRequest> captor = ArgumentCaptor.forClass(StoreInviteAuthRequest.class);
        verify(authPipelineService).verifyDeviceManagerRequest(captor.capture());
        StoreInviteAuthRequest authRequestData = captor.getValue();

        verify(invitationService).createInvite(
            any(UUID.class),
            eq(request.inviteToken()),
            eq(request.deviceType())
        );

        assertThat(authRequestData.devicePublicId()).isEqualTo(request.devicePublicId());
        assertThat(authRequestData.inviteToken()).isEqualTo(request.inviteToken());
        assertThat(authRequestData.nonce()).isEqualTo(request.nonce());
        assertThat(authRequestData.base64Signature()).isEqualTo(request.base64Signature());
        assertThat(authRequestData.deviceType()).isEqualTo(request.deviceType());
        assertThat(authRequestData.keyVersion()).isEqualTo(request.keyVersion());
        assertThat(response).isNotNull();
        assertThat(response.expiresAt()).isEqualTo(expiredAt);
    }

    @Test
    void storeInviteToken_shouldThrow_whenDeviceMasterKeyVersionOutdated() {
        DeviceType deviceType = DeviceType.MOBILE;
        AuthData authData = new AuthData(
            new UserAuthData(1L, UUID.randomUUID(), 99),
            new DeviceAuthData(
                1L,
                UUID.randomUUID(),
                UUID.randomUUID(),
                DeviceType.MOBILE,
                mock(PublicKey.class)
            )
        );
        when(authPipelineService.verifyDeviceManagerRequest(any())).thenReturn(authData);

        var request = new StoreInviteRequestDto(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            1,
            deviceType,
            UUID.randomUUID(),
            Base64.getEncoder().encodeToString(new byte[64])
        );

        assertThatThrownBy(() -> deviceRegistrationService.storeInviteToken(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_MASTER_KEY_VERSION_MISMATCH)
            );

        verify(invitationService, never()).createInvite(any(), any(), any());
    }

    @Test
    void registerDevice_whenUserAlreadyHaveActiveDevice_shouldRegisterAnotherOne() {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64EncryptedMasterKey(ctx.encryptedMasterKey());
        deviceInviteData.setBase64SigningPublicKey(request.base64PublicKey());
        deviceInviteData.setKeyVersion(1);
        deviceInviteData.setDeviceType(deviceType);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);
        doNothing().when(invitationService).lockDeviceInviteData(any(), any());
        when(invitationService.deleteDeviceInviteData(any(), any())).thenReturn(true);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(keySignatureService.extractPublicKeyBytes(any())).thenReturn(ctx.publicKeyBytes());
        doNothing().when(deviceService).saveWithRetry(any());

        DeviceRegisterResponseDto response = deviceRegistrationService.registerDevice(request);

        ArgumentCaptor<RegistrationAuthRequest> captor = ArgumentCaptor.forClass(RegistrationAuthRequest.class);
        verify(authPipelineService).verifyUnregisteredDeviceRequest(captor.capture());
        RegistrationAuthRequest authRequestData = captor.getValue();

        assertThat(authRequestData.base64Signature()).isEqualTo(request.base64Signature());
        assertThat(authRequestData.nonce()).isEqualTo(request.nonce());
        assertThat(authRequestData.inviteToken()).isEqualTo(request.inviteToken());
        assertThat(authRequestData.base64SigningPublicKey()).isEqualTo(request.base64PublicKey());
        assertThat(authRequestData.deviceName()).isEqualTo(request.deviceName());
        assertThat(authRequestData.extras()).isEqualTo(request.extras());
        verify(invitationService).lockDeviceInviteData(ctx.jwtUserData().authId(), request.inviteToken());
        verify(invitationService).deleteDeviceInviteData(ctx.jwtUserData().authId(), request.inviteToken());
        assertThat(response.devicePublicId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(request.deviceName());
        assertThat(response.encryptedMasterKey()).isEqualTo(ctx.encryptedMasterKey());
        assertThat(response.keyVersion()).isEqualTo(deviceInviteData.getKeyVersion());
    }

    @Test
    void registerDevice_whenInviteLockFails_shouldThrow() {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64EncryptedMasterKey(ctx.encryptedMasterKey());
        deviceInviteData.setBase64SigningPublicKey(request.base64PublicKey());
        deviceInviteData.setKeyVersion(1);
        deviceInviteData.setDeviceType(deviceType);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);
        doThrow(DeviceRegistrationException.invalidInvite("Invite is already being consumed"))
            .when(invitationService).lockDeviceInviteData(any(), any());

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOf(DeviceRegistrationException.class);

        verifyNoInteractions(userService, keySignatureService, deviceService);
        verify(invitationService, never()).deleteDeviceInviteData(any(), any());
    }

    @Test
    void registerDevice_whenInviteDeleteFails_shouldThrow() {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64EncryptedMasterKey(ctx.encryptedMasterKey());
        deviceInviteData.setBase64SigningPublicKey(request.base64PublicKey());
        deviceInviteData.setKeyVersion(1);
        deviceInviteData.setDeviceType(deviceType);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);
        doNothing().when(invitationService).lockDeviceInviteData(any(), any());
        when(invitationService.deleteDeviceInviteData(any(), any())).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(keySignatureService.extractPublicKeyBytes(any())).thenReturn(ctx.publicKeyBytes());
        doNothing().when(deviceService).saveWithRetry(any());

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_DEFAULT);
            });

        verify(deviceService).saveWithRetry(any());
        verify(invitationService).deleteDeviceInviteData(ctx.jwtUserData().authId(), request.inviteToken());
    }

    @Test
    void registerDevice_whenInviteDeviceTypeMismatch_shouldThrowBeforeLockAndSave() {
        var ctx = createContext(DeviceType.DESKTOP);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64EncryptedMasterKey(ctx.encryptedMasterKey());
        deviceInviteData.setBase64SigningPublicKey(request.base64PublicKey());
        deviceInviteData.setKeyVersion(1);
        deviceInviteData.setDeviceType(DeviceType.BROWSER);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOf(InvalidDeviceTypeException.class);

        verify(invitationService, never()).lockDeviceInviteData(any(), any());
        verify(invitationService, never()).deleteDeviceInviteData(any(), any());
        verifyNoInteractions(userService, keySignatureService, deviceService);
    }

    @Test
    void registerDevice_whenInviteSigningPublicKeyMismatch_shouldThrowBeforeLockAndSave() {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64EncryptedMasterKey(ctx.encryptedMasterKey());
        deviceInviteData.setBase64SigningPublicKey("b".repeat(44));
        deviceInviteData.setKeyVersion(1);
        deviceInviteData.setDeviceType(deviceType);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_INVALID_INVITE);
            });

        verify(invitationService, never()).lockDeviceInviteData(any(), any());
        verify(invitationService, never()).deleteDeviceInviteData(any(), any());
        verifyNoInteractions(userService, keySignatureService, deviceService);
    }

    @Test
    void registerDevice_whenMasterKeyNotReady_shouldThrowBeforeLockAndSave() {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setBase64SigningPublicKey(request.base64PublicKey());
        deviceInviteData.setDeviceType(deviceType);

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(true);
        when(invitationService.getDeviceInviteData(any(), any())).thenReturn(deviceInviteData);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_INVALID_INVITE);
            });

        verify(invitationService, never()).lockDeviceInviteData(any(), any());
        verify(invitationService, never()).deleteDeviceInviteData(any(), any());
        verifyNoInteractions(userService, keySignatureService, deviceService);
    }

    @Test
    void registerDevice_whenUserNotHaveActiveDevices_shouldCreateFirstMobileDevice() {
        DeviceType deviceType = DeviceType.MOBILE;

        var ctx = createContext(deviceType);
        var request = deviceRegistrationRequest();

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(keySignatureService.extractPublicKeyBytes(any())).thenReturn(ctx.publicKeyBytes());
        doNothing().when(deviceService).saveWithRetry(any());

        DeviceRegisterResponseDto response = deviceRegistrationService.registerDevice(request);

        verifyNoInteractions(invitationService);

        assertThat(response.devicePublicId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(request.deviceName());
        assertThat(response.encryptedMasterKey()).isNull();
    }

    @Test
    void registerDevice_whenFirstDeviceTypeNotMobile_shouldThrow() {
        var ctx = createContext(DeviceType.BROWSER);
        var request = deviceRegistrationRequest();

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.jwtUserData().authId()))).thenReturn(false);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_FIRST_DEVICE_TYPE);
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

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_INVALID_INVITE);
            });

        verifyNoInteractions(invitationService);
    }

    @Test
    void registerDevice_whenUserSavingError_shouldThrow() {
        var ctx = createContext(DeviceType.MOBILE);
        var request = deviceRegistrationRequest();

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenThrow(IllegalStateException.class);

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                    assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                    assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_DEFAULT);
                    assertThat(e.getCause()).isInstanceOf(IllegalStateException.class);
                }
            );

        verifyNoInteractions(keySignatureService);
    }

    @Test
    void registerDevice_whenDeviceSavingError_shouldThrow() {
        var ctx = createContext(DeviceType.MOBILE);
        var request = deviceRegistrationRequest();

        when(authPipelineService.verifyUnregisteredDeviceRequest(any())).thenReturn(authPipelineResult(ctx));
        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(keySignatureService.extractPublicKeyBytes(any())).thenReturn(ctx.publicKeyBytes());
        doThrow(DeviceException.class).when(deviceService).saveWithRetry(any());

        assertThatThrownBy(() -> deviceRegistrationService.registerDevice(request))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                    assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                    assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.REGISTRATION_DEFAULT);
                    assertThat(e.getCause()).isInstanceOf(DeviceException.class);
                }
            );

        verify(keySignatureService).extractPublicKeyBytes(any());
    }


    private record TestContext(
        User user,
        String encryptedMasterKey,
        JwtUserData jwtUserData,
        AuthData authData,
        byte[] publicKeyBytes
    ) {
    }

    private TestContext createContext(DeviceType deviceType) {
        UUID authId = UUID.randomUUID();
        String encryptedMasterKey = "base64EncryptedMasterKey";
        String email = "test@mail.com";
        String clientId = deviceType.getClientId();
        JwtUserData jwtUserData = new JwtUserData(authId, clientId, email, true);

        User user = new User();
        user.setId(1L);
        user.setEmail(email);
        user.setAuthId(authId);

        PublicKey publicKey = mock(PublicKey.class);
        AuthData authData = new AuthData(
            new UserAuthData(1L, authId, 1),
            new DeviceAuthData(null, null, authId, deviceType, publicKey)
        );

        return new TestContext(user, encryptedMasterKey, jwtUserData, authData, new byte[]{1, 2, 3});
    }

    private AuthPipelineResult authPipelineResult(TestContext context) {
        return new AuthPipelineResult(
            context.authData(),
            context.jwtUserData()
        );
    }

    DeviceRegisterRequestDto deviceRegistrationRequest() {
        return new DeviceRegisterRequestDto(
            "test device",
            "a".repeat(44),
            Map.of("platform", "android"),
            TestModelFactory.inviteToken(),
            UUID.randomUUID(),
            "a".repeat(80)
        );
    }

    StoreInviteRequestDto storeInviteRequestDto() {
        return new StoreInviteRequestDto(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            2,
            DeviceType.MOBILE,
            UUID.randomUUID(),
            Base64.getEncoder().encodeToString(new byte[64])
        );
    }

}
