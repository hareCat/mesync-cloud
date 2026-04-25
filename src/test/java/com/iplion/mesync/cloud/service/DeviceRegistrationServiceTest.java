package com.iplion.mesync.cloud.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterRequestDto;
import com.iplion.mesync.cloud.controller.dto.DeviceRegisterResponseDto;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.CryptoException;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.infrastructure.redis.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.testUtils.TestJwtBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
    RedisSecurityStore redisSecurityStore;
    @Mock
    RegistrationCryptoService registrationCryptoService;
    @Mock
    ObjectMapper objectMapper;

    private final ObjectMapper testObjectMapper = new ObjectMapper();

    @Test
    void registerDevice_whenUserAlreadyHaveActiveDevice_shouldRegisterAnotherOne() throws Exception {
        DeviceType deviceType = DeviceType.DESKTOP;

        var ctx = createContext(deviceType);

        when(redisSecurityStore.incrementWithTtl(any(), any())).thenReturn(1L);
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.authId()))).thenReturn(true);
        when(registrationCryptoService.verifyAngExtractPublicKeyBytes(any())).thenReturn(ctx.decodedPublicKey());
        when(invitationService.consumeInviteAndGetEncryptedMasterKey(any(), any(), any()))
            .thenReturn(ctx.encryptedMasterKey());
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(objectMapper.writeValueAsString(any()))
            .thenReturn(testObjectMapper.writeValueAsString(ctx.request().extras()));

        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(1);

        DeviceRegisterResponseDto response = ctx.service().registerDevice(ctx.jwt(), ctx.request());

        verify(deviceRepository, times(1)).trySave(
            any(),
            eq(ctx.user().getId()),
            eq(deviceType.name()),
            eq(ctx.request().name()),
            argThat(bytes -> Arrays.equals(bytes, ctx.decodedPublicKey())),
            any(), any(),
            argThat(json -> json.contains("platform"))
        );

        assertThat(response.deviceId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(ctx.request().name());
        assertThat(response.encryptedMasterKey()).isEqualTo(ctx.encryptedMasterKey());
    }

    @Test
    void registerDevice_whenUserNotHaveActiveDevices_shouldCreateFirstMobileDevice() throws Exception {
        DeviceType deviceType = DeviceType.MOBILE;

        var ctx = createContext(deviceType);

        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.authId()))).thenReturn(false);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(1);

        DeviceRegisterResponseDto response = ctx.service().registerDevice(ctx.jwt(), ctx.request());

        verify(invitationService, never()).consumeInviteAndGetEncryptedMasterKey(any(), any(), any());

        verify(deviceRepository, times(1)).trySave(
            any(), any(),
            eq(deviceType.name()),
            any(), any(), any(), any(), any()
        );

        assertThat(response.deviceId()).isNotNull();
        assertThat(response.deviceName()).isEqualTo(ctx.request().name());
        assertThat(response.encryptedMasterKey()).isNull();
    }

    @Test
    void registerDevice_whenTooMuchTriesForRegister_shouldThrowDeviceRegistrationExceptionWithRateLimit() throws NoSuchAlgorithmException {
        var ctx = createContext(DeviceType.BROWSER);

        when(redisSecurityStore.incrementWithTtl(any(), any()))
            .thenReturn(ctx.props().registrationAttempts() + 1);

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                assertThat(e.getMessage()).contains("rate limit");
            });

        verify(redisSecurityStore).incrementWithTtl(contains(ctx.authId().toString()), eq(ctx.props().registrationTtl()));
    }

    @Test
    void registerDevice_whenDeviceTypeMismatch_shouldThrowDeviceRegistrationExceptionWithDeviceTypeMismatch() throws NoSuchAlgorithmException {
        var ctx = createContext(DeviceType.BROWSER);

        Jwt jwt = TestJwtBuilder
            .forDevice(ctx.authId(), DeviceType.MOBILE)
            .buildJwt();

        assertThatThrownBy(() -> ctx.service().registerDevice(jwt, ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("type mismatch");
            });

    }

    @Test
    void registerDevice_whenDeviceTypeMismatch_shouldThrowDeviceRegistrationExceptionWithFirstDeviceType() throws NoSuchAlgorithmException {
        var ctx = createContext(DeviceType.BROWSER);

        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(false);

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("not mobile");
            });
    }

    @Test
    void registerDevice_whenSignatureVerificationFailed_shouldThrowDeviceRegistrationExceptionWithInvalidSignature() throws NoSuchAlgorithmException {
        var ctx = createContext(DeviceType.MOBILE);

        doThrow(CryptoException.class).when(registrationCryptoService).verifyAngExtractPublicKeyBytes(any());

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .hasCauseInstanceOf(CryptoException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains(ctx.authId().toString());
            });
    }

    @Test
    void registerDevice_whenRequestInviteTokenMissing_shouldThrowDeviceRegistrationExceptionWithInvalidInvite() throws NoSuchAlgorithmException {
        DeviceType deviceType = DeviceType.MOBILE;

        var ctx = createContext(deviceType);

        DeviceRegisterRequestDto request = new DeviceRegisterRequestDto(
            "test device",
            deviceType,
            "base64PublicKey",
            Map.of("platform", "android"),
            null,
            "base64Signature"
        );

        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), request))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("invite");
            });
    }

    @Test
    void registerDevice_saveWithRetry_shouldThrowDeviceRegistrationExceptionWithSaveFailedThreeTimes() throws NoSuchAlgorithmException {
        var ctx = createContext(DeviceType.MOBILE);

        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0);

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getMessage()).contains("device");
            });

        verify(deviceRepository, times(3)).trySave(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void registerDevice_saveWithRetry_shouldSaveDeviceWithNewNameWithDeviceType() throws NoSuchAlgorithmException {
        DeviceType deviceType = DeviceType.MOBILE;
        var ctx = createContext(deviceType);
        String generatedDeviceName = ctx.request().name() + "-" + deviceType.name().toLowerCase();

        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)
            .thenReturn(1);

        DeviceRegisterResponseDto response = ctx.service().registerDevice(ctx.jwt(), ctx.request());

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(deviceRepository, times(2)).trySave(
            any(), any(), any(),
            captor.capture(),
            any(), any(), any(), any()
        );
        List<String> names = captor.getAllValues();

        assertThat(names.get(0)).isEqualTo(ctx.request().name());
        assertThat(names.get(1))
            .isEqualTo(generatedDeviceName)
            .isEqualTo(response.deviceName());
    }

    @Test
    void registerDevice_saveWithRetry_shouldSaveDeviceWithNewRandomName() throws NoSuchAlgorithmException {
        DeviceType deviceType = DeviceType.MOBILE;
        var ctx = createContext(deviceType);

        when(deviceRepository.existsActiveByUserAuthId(any())).thenReturn(true);
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());
        when(deviceRepository.trySave(any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)
            .thenReturn(0)
            .thenReturn(1);

        DeviceRegisterResponseDto response = ctx.service().registerDevice(ctx.jwt(), ctx.request());

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(deviceRepository, times(3)).trySave(
            any(), any(), any(),
            captor.capture(),
            any(), any(), any(), any()
        );
        List<String> names = captor.getAllValues();

        assertThat(names.get(2))
            .isNotEqualTo(ctx.request().name())
            .startsWith(ctx.request().name())
            .hasSizeGreaterThan(ctx.request().name().length())
            .isEqualTo(response.deviceName());
    }

    @Test
    void registerDevice_whenRequestExtrasWrong_shouldThrowDeviceRegistrationExceptionWithDecodeError() throws Exception {
        var ctx = createContext(DeviceType.DESKTOP);

        when(redisSecurityStore.incrementWithTtl(any(), any())).thenReturn(1L);
        when(deviceRepository.existsActiveByUserAuthId(eq(ctx.authId()))).thenReturn(true);
        when(registrationCryptoService.verifyAngExtractPublicKeyBytes(any())).thenReturn(ctx.decodedPublicKey());
        when(userService.syncOrCreateUser(any(), any(), anyBoolean())).thenReturn(ctx.user());

        doThrow(JsonProcessingException.class).when(objectMapper).writeValueAsString(any());

        assertThatThrownBy(() -> ctx.service().registerDevice(ctx.jwt(), ctx.request()))
            .isInstanceOf(DeviceRegistrationException.class)
            .satisfies(deviceRegistrationException -> {
                DeviceRegistrationException e = (DeviceRegistrationException) deviceRegistrationException;

                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("Extras");
            });

        verify(objectMapper).writeValueAsString(any());
    }

    // --------------------- helpers ---------------------

    private record TestContext(
        DeviceRegistrationService service,
        DeviceRegisterRequestDto request,
        User user,
        UUID authId,
        byte[] decodedPublicKey,
        String encryptedMasterKey,
        RegistrationProperties props,
        Jwt jwt
    ) {
    }

    private TestContext createContext(DeviceType deviceType) throws NoSuchAlgorithmException {
        final RegistrationProperties props = new RegistrationProperties(
            Duration.ofMinutes(10),
            Duration.ofSeconds(60),
            Duration.ofMinutes(10),
            10
        );

        DeviceRegistrationService service = new DeviceRegistrationService(
            deviceRepository,
            userService,
            invitationService,
            redisSecurityStore,
            props,
            registrationCryptoService,
            objectMapper
        );

        UUID authId = UUID.randomUUID();
        String encryptedMasterKey = "encryptedMasterKey";
        String email = "test@mail.com";

        User user = new User();
        user.setId(1L);
        user.setEmail(email);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        PublicKey publicKey = generator.generateKeyPair().getPublic();
        byte[] decodedPublicKey = publicKey.getEncoded();

        DeviceRegisterRequestDto request = new DeviceRegisterRequestDto(
            "test device",
            deviceType,
            "base64PublicKey",
            Map.of("platform", "android"),
            UUID.randomUUID(),
            "base64Signature"
        );

        Jwt jwt = TestJwtBuilder
            .forDevice(authId, deviceType)
            .buildJwt();

        return new TestContext(service, request, user, authId, decodedPublicKey, encryptedMasterKey, props, jwt);
    }
}
