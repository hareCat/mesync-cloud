package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.RegistrationProperties;
import com.iplion.mesync.cloud.error.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.infrastructure.redis.RedisKeys;
import com.iplion.mesync.cloud.infrastructure.redis.RedisStore;
import com.iplion.mesync.cloud.model.DeviceInviteData;
import com.iplion.mesync.cloud.model.DeviceType;
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
    RedisStore redisStore;

    RegistrationProperties props = new RegistrationProperties(
        Duration.ofMinutes(10),
        Duration.ofSeconds(60),
        Duration.ofMinutes(10),
        10
    );

    InvitationService invitationService;

    @BeforeEach
    public void setUp() {
        invitationService = new InvitationService(redisStore, props);
    }

    @Test
    public void createInvite_whenSetIfAbsentFail_shouldThrowDeviceRegistrationExceptionWithCooldownDelay() {
        when(redisStore.setIfAbsent(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> invitationService.createInvite(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            DeviceType.MOBILE)
        )
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                assertThat(e.getMessage()).contains("cooldown");
            });
    }

    @Test
    public void createInvite_whenSetRedisValueFail_shouldThrowDeviceRegistrationExceptionWithRedisSetValueError() {
        UUID authId = UUID.randomUUID();

        when(redisStore.setIfAbsent(any(), any(), any()))
            .thenThrow(new RedisOperationException("error"))
            .thenReturn(true);

        assertThatThrownBy(() -> invitationService.createInvite(
            authId,
            UUID.randomUUID(),
            "encryptedMasterKey",
            DeviceType.MOBILE)
        )
            .hasMessageContaining(authId.toString())
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getCause()).isInstanceOf(RedisOperationException.class);
            });

        doThrow(new RedisOperationException("error")).when(redisStore).set(any(), any(), any());

        assertThatThrownBy(() -> invitationService.createInvite(
            authId,
            UUID.randomUUID(),
            "encryptedMasterKey",
            DeviceType.MOBILE)
        )
            .hasMessageContaining(authId.toString())
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getCause()).isInstanceOf(RedisOperationException.class);
            });
    }

    @Test
    public void createInvite_shouldCreateInviteAndReturnExpiredAt() {
        UUID authId = UUID.randomUUID();
        UUID inviteToken = UUID.randomUUID();
        Instant expiresAt = Instant.now().plus(props.inviteTtl());
        DeviceType deviceType = DeviceType.MOBILE;
        String encryptedMasterKey = "encryptedMasterKey";
        var deviceInviteData = new DeviceInviteData(
            encryptedMasterKey,
            deviceType
        );

        when(redisStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        doNothing().when(redisStore).set(any(), any(), any());

        assertThat(
            invitationService.createInvite(
                authId,
                inviteToken,
                encryptedMasterKey,
                deviceType)
        ).isAfterOrEqualTo(expiresAt);

        verify(redisStore).setIfAbsent(
            eq(RedisKeys.registrationInviteCooldownKey(authId)),
            any(String.class),
            eq(props.inviteCooldown())
        );
        verify(redisStore).set(
            eq(RedisKeys.registrationInviteKey(authId, inviteToken)),
            eq(deviceInviteData),
            eq(props.inviteTtl())
        );
    }

    @Test
    public void consumeInviteAndGetEncryptedMasterKey_whenSetRedisValueFail_shouldThrowDeviceRegistrationExceptionWithRedisSetValueError() {
        UUID authId = UUID.randomUUID();

        when(redisStore.getAndDelete(any(), any()))
            .thenThrow(new RedisOperationException("error"));

        assertThatThrownBy(() -> invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            DeviceType.MOBILE,
            UUID.randomUUID()
        ))
            .hasMessageContaining(authId.toString())
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getCause()).isInstanceOf(RedisOperationException.class);
            });
    }

    @Test
    public void consumeInviteAndGetEncryptedMasterKey_whenRedisReturnsNull_shouldThrowDeviceRegistrationExceptionWithInvalidInvite() {
        UUID authId = UUID.randomUUID();

        when(redisStore.getAndDelete(any(), any()))
            .thenReturn(null);

        assertThatThrownBy(() -> invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            DeviceType.MOBILE,
            UUID.randomUUID()
        ))
            .hasMessageContaining(authId.toString())
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("expired");
            });
    }

    @Test
    public void consumeInviteAndGetEncryptedMasterKey_whenDeviceTypeMismatch_shouldThrowDeviceRegistrationExceptionWithDeviceTypeMismatch() {
        UUID authId = UUID.randomUUID();
        DeviceType inviteDeviceType = DeviceType.MOBILE;
        DeviceType requestDeviceType = DeviceType.BROWSER;
        DeviceInviteData deviceInviteData = new DeviceInviteData(
            "encryptedMasterKey",
            inviteDeviceType
        );

        when(redisStore.getAndDelete(any(), any()))
            .thenReturn(deviceInviteData);

        assertThatThrownBy(() -> invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            requestDeviceType,
            UUID.randomUUID()
        ))
            .hasMessageContaining(authId.toString(), inviteDeviceType.name(), requestDeviceType.name())
            .isInstanceOfSatisfying(
                DeviceRegistrationException.class,
                e -> assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST)
            );
    }

    @Test
    public void consumeInviteAndGetEncryptedMasterKey_shouldReturnEncryptedMasterKey() {
        UUID authId = UUID.randomUUID();
        UUID inviteToken = UUID.randomUUID();
        DeviceType deviceType = DeviceType.MOBILE;
        DeviceInviteData deviceInviteData = new DeviceInviteData(
            "encryptedMasterKey",
            deviceType
        );

        when(redisStore.getAndDelete(any(), any()))
            .thenReturn(deviceInviteData);

        assertThat(invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            deviceType,
            inviteToken
        )).isEqualTo(deviceInviteData.encryptedMasterKey());

        verify(redisStore).getAndDelete(eq(RedisKeys.registrationInviteKey(authId, inviteToken)), any());
    }

}
