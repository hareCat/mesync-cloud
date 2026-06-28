package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.api.RedisOperationException;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class InvitationServiceTest {
    @Mock
    RedisSecurityStore redisSecurityStore;

    AppProperties appProperties = new AppProperties(
        new AppProperties.Registration(
            Duration.ofMinutes(10),
            Duration.ofSeconds(10),
            Duration.ofSeconds(30),
            Duration.ofMinutes(10),
            10
        ),
        null,
        null,
        null
    );
    AppProperties.Registration regProps = appProperties.registration();

    InvitationService invitationService;

    @BeforeEach
    public void setUp() {
        invitationService = new InvitationService(redisSecurityStore, appProperties);
    }

    @Test
    public void createInvite_whenSetIfAbsentFail_shouldThrowDeviceRegistrationExceptionWithCooldownDelay() {
        UUID authId = UUID.randomUUID();
        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> invitationService.createInvite(
            authId,
            TestModelFactory.inviteToken(),
            DeviceType.MOBILE)
        )
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains("cooldown");
            });
    }

    @Test
    public void createInvite_whenSetIfAbsentRedisOperationFails_shouldThrowRedisOperationException() {
        when(redisSecurityStore.setIfAbsent(any(), any(), any()))
            .thenThrow(new RedisOperationException("error"));

        assertThatThrownBy(() -> invitationService.createInvite(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            DeviceType.MOBILE)
        )
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("error");
    }

    @Test
    public void createInvite_whenSetRedisValueFail_shouldThrowRedisOperationException() {
        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);

        doThrow(new RedisOperationException("error")).when(redisSecurityStore).set(any(), any(), any());

        assertThatThrownBy(() -> invitationService.createInvite(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            DeviceType.MOBILE)
        )
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("error");
    }

    @Test
    public void createInvite_shouldCreateInviteAndReturnExpiredAt() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();
        Instant expiresAt = Instant.now().plus(regProps.inviteTtl());
        DeviceType deviceType = DeviceType.MOBILE;

        var deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(deviceType);

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        doNothing().when(redisSecurityStore).set(any(), any(), any());

        assertThat(
            invitationService.createInvite(
                authId,
                inviteToken,
                deviceType)
        ).isAfterOrEqualTo(expiresAt);

        verify(redisSecurityStore).setIfAbsent(
            eq(RedisKeys.registrationInviteCooldownKey(authId)),
            any(String.class),
            eq(regProps.inviteCooldown())
        );
        verify(redisSecurityStore).set(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(deviceInviteData),
            eq(regProps.inviteTtl())
        );
    }

    @Test
    public void storePublicKeys_whenSetIfAbsentFails_shouldThrowDeviceRegistrationExceptionWithCooldownDelay() {
        UUID authId = UUID.randomUUID();
        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> invitationService.storePublicKeys(
            authId,
            TestModelFactory.inviteToken(),
            "encryptionPublicKey",
            "signingPublicKey"
        ))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains("cooldown");
            });
    }

    @Test
    public void storePublicKeys_whenGetRedisValueFails_shouldThrowRedisOperationException() {
        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenThrow(new RedisOperationException("error"));

        assertThatThrownBy(() -> invitationService.storePublicKeys(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            "encryptionPublicKey",
            "signingPublicKey"
        ))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("error");
    }

    @Test
    public void storePublicKeys_whenSetRedisValueFails_shouldThrowRedisOperationException() {
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(DeviceType.MOBILE);

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenReturn(deviceInviteData);
        doThrow(new RedisOperationException("error")).when(redisSecurityStore).set(any(), any(), any());

        assertThatThrownBy(() -> invitationService.storePublicKeys(
            UUID.randomUUID(),
            TestModelFactory.inviteToken(),
            "encryptionPublicKey",
            "signingPublicKey"
        ))
            .isInstanceOf(RedisOperationException.class)
            .hasMessageContaining("error");
    }

    @Test
    public void storePublicKeys_whenRedisReturnsNull_shouldThrowDeviceRegistrationExceptionWithInvalidInvite() {
        UUID authId = UUID.randomUUID();

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenReturn(null);

        assertThatThrownBy(() -> invitationService.storePublicKeys(
            authId,
            TestModelFactory.inviteToken(),
            "encryptionPublicKey",
            "signingPublicKey"
        ))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("expired");
            });
    }

    @Test
    public void storePublicKeys_shouldUpdateInviteAndReturnExpiredAt() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();
        String encryptionPublicKey = "encryptionPublicKey";
        String signingPublicKey = "signingPublicKey";
        Instant expiresAt = Instant.now().plus(regProps.inviteTtl());
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(DeviceType.MOBILE);

        DeviceInviteData expectedInviteData = new DeviceInviteData();
        expectedInviteData.setDeviceType(DeviceType.MOBILE);
        expectedInviteData.setBase64EncryptionPublicKey(encryptionPublicKey);
        expectedInviteData.setBase64SigningPublicKey(signingPublicKey);

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenReturn(deviceInviteData);
        doNothing().when(redisSecurityStore).set(any(), any(), any());

        assertThat(invitationService.storePublicKeys(
            authId,
            inviteToken,
            encryptionPublicKey,
            signingPublicKey
        )).isAfterOrEqualTo(expiresAt);

        verify(redisSecurityStore).setIfAbsent(
            eq(RedisKeys.registrationPublicKeyCooldownKey(authId)),
            any(String.class),
            eq(regProps.inviteCooldown())
        );
        verify(redisSecurityStore).get(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(DeviceInviteData.class)
        );
        verify(redisSecurityStore).set(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(expectedInviteData),
            eq(regProps.inviteTtl())
        );
    }

    @Test
    public void storeMasterKey_whenPublicKeysMissing_shouldThrowInvalidInvite() {
        UUID authId = UUID.randomUUID();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(DeviceType.MOBILE);

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenReturn(deviceInviteData);

        assertThatThrownBy(() -> invitationService.storeMasterKey(
            authId,
            TestModelFactory.inviteToken(),
            "encryptedMasterKey",
            1
        ))
            .isInstanceOfSatisfying(
                DeviceRegistrationException.class,
                e -> assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST)
            );
    }

    @Test
    public void storeMasterKey_shouldUpdateInviteAndReturnExpiredAt() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();
        String encryptedMasterKey = "encryptedMasterKey";
        int keyVersion = 1;
        Instant expiresAt = Instant.now().plus(regProps.inviteTtl());
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(DeviceType.MOBILE);
        deviceInviteData.setBase64EncryptionPublicKey("encryptionPublicKey");
        deviceInviteData.setBase64SigningPublicKey("signingPublicKey");

        DeviceInviteData expectedInviteData = new DeviceInviteData();
        expectedInviteData.setDeviceType(DeviceType.MOBILE);
        expectedInviteData.setBase64EncryptionPublicKey("encryptionPublicKey");
        expectedInviteData.setBase64SigningPublicKey("signingPublicKey");
        expectedInviteData.setBase64EncryptedMasterKey(encryptedMasterKey);
        expectedInviteData.setKeyVersion(keyVersion);

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        when(redisSecurityStore.get(any(), any())).thenReturn(deviceInviteData);
        doNothing().when(redisSecurityStore).set(any(), any(), any());

        assertThat(invitationService.storeMasterKey(
            authId,
            inviteToken,
            encryptedMasterKey,
            keyVersion
        )).isAfterOrEqualTo(expiresAt);

        verify(redisSecurityStore).setIfAbsent(
            eq(RedisKeys.registrationMasterKeyCooldownKey(authId)),
            any(String.class),
            eq(regProps.inviteCooldown())
        );
        verify(redisSecurityStore).set(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(expectedInviteData),
            eq(regProps.inviteTtl())
        );
    }

    @Test
    public void getDeviceInviteData_whenRedisReturnsNull_shouldThrowInvalidInvite() {
        UUID authId = UUID.randomUUID();
        when(redisSecurityStore.get(any(), any())).thenReturn(null);

        assertThatThrownBy(() -> invitationService.getDeviceInviteData(authId, TestModelFactory.inviteToken()))
            .isInstanceOfSatisfying(
                DeviceRegistrationException.class,
                e -> assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST)
            );
    }

    @Test
    public void getDeviceInviteData_shouldReturnInviteData() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();
        DeviceInviteData deviceInviteData = new DeviceInviteData();
        deviceInviteData.setDeviceType(DeviceType.MOBILE);

        when(redisSecurityStore.get(any(), any())).thenReturn(deviceInviteData);

        assertThat(invitationService.getDeviceInviteData(authId, inviteToken)).isEqualTo(deviceInviteData);

        verify(redisSecurityStore).get(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(DeviceInviteData.class)
        );
    }

    @Test
    public void lockDeviceInviteData_whenSetIfAbsentFails_shouldThrowCooldownDelay() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> invitationService.lockDeviceInviteData(authId, inviteToken))
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains("cooldown");
            });
    }

    @Test
    public void lockDeviceInviteData_shouldCreateLastStepLock() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);

        invitationService.lockDeviceInviteData(authId, inviteToken);

        verify(redisSecurityStore).setIfAbsent(
            eq(RedisKeys.registrationLastStepCooldownKey(authId, inviteToken)),
            any(String.class),
            eq(regProps.inviteCooldown())
        );
    }

    @Test
    public void deleteDeviceInviteData_shouldDeleteInviteKey() {
        UUID authId = UUID.randomUUID();
        String inviteToken = TestModelFactory.inviteToken();

        when(redisSecurityStore.delete(any())).thenReturn(true);

        assertThat(invitationService.deleteDeviceInviteData(authId, inviteToken)).isTrue();

        verify(redisSecurityStore).delete(eq(RedisKeys.registrationInviteKey(authId, inviteToken)));
    }

}
