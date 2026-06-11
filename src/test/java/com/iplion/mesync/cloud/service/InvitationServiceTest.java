package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.security.cache.RedisKeys;
import com.iplion.mesync.cloud.security.cache.RedisSecurityStore;
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
    RedisSecurityStore redisSecurityStore;

    AppProperties appProperties = new AppProperties(
        new AppProperties.Registration(
            Duration.ofMinutes(10),
            Duration.ofSeconds(60),
            Duration.ofMinutes(10),
            Duration.ofSeconds(30),
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
        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(false);

        assertThatThrownBy(() -> invitationService.createInvite(
            UUID.randomUUID(),
            UUID.randomUUID(),
            "encryptedMasterKey",
            1,
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

        when(redisSecurityStore.setIfAbsent(any(), any(), any()))
            .thenThrow(new RedisOperationException("error"))
            .thenReturn(true);

        assertThatThrownBy(() -> invitationService.createInvite(
            authId,
            UUID.randomUUID(),
            "encryptedMasterKey",
            1,
            DeviceType.MOBILE)
        )
            .hasMessageContaining(authId.toString())
            .isInstanceOfSatisfying(DeviceRegistrationException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                assertThat(e.getCause()).isInstanceOf(RedisOperationException.class);
            });

        doThrow(new RedisOperationException("error")).when(redisSecurityStore).set(any(), any(), any());

        assertThatThrownBy(() -> invitationService.createInvite(
            authId,
            UUID.randomUUID(),
            "encryptedMasterKey",
            1,
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
        Instant expiresAt = Instant.now().plus(regProps.inviteTtl());
        DeviceType deviceType = DeviceType.MOBILE;
        String encryptedMasterKey = "encryptedMasterKey";
        Integer keyVersion = 1;
        var deviceInviteData = new DeviceInviteData(
            encryptedMasterKey,
            keyVersion,
            deviceType
        );

        when(redisSecurityStore.setIfAbsent(any(), any(), any())).thenReturn(true);
        doNothing().when(redisSecurityStore).set(any(), any(), any());

        assertThat(
            invitationService.createInvite(
                authId,
                inviteToken,
                encryptedMasterKey,
                keyVersion,
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
    public void consumeInviteAndGetEncryptedMasterKey_whenSetRedisValueFail_shouldThrowDeviceRegistrationExceptionWithRedisSetValueError() {
        UUID authId = UUID.randomUUID();

        when(redisSecurityStore.getAndDelete(any(), any()))
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

        when(redisSecurityStore.getAndDelete(any(), any()))
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
            1,
            inviteDeviceType
        );

        when(redisSecurityStore.getAndDelete(any(), any()))
            .thenReturn(deviceInviteData);

        assertThatThrownBy(() -> invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            requestDeviceType,
            UUID.randomUUID()
        ))
            .hasMessageContaining(authId.toString(), inviteDeviceType.name(), requestDeviceType.name())
            .isInstanceOfSatisfying(
                DeviceRegistrationException.class,
                e -> assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN)
            );
    }

    @Test
    public void consumeInviteAndGetEncryptedMasterKey_shouldReturnEncryptedMasterKey() {
        UUID authId = UUID.randomUUID();
        UUID inviteToken = UUID.randomUUID();
        DeviceType deviceType = DeviceType.MOBILE;
        DeviceInviteData deviceInviteData = new DeviceInviteData(
            "encryptedMasterKey",
            1,
            deviceType
        );

        when(redisSecurityStore.getAndDelete(any(), any()))
            .thenReturn(deviceInviteData);

        assertThat(invitationService.consumeInviteAndGetEncryptedMasterKey(
            authId,
            deviceType,
            inviteToken
        )).isEqualTo(deviceInviteData);

        verify(redisSecurityStore).getAndDelete(eq(RedisKeys.registrationInviteKey(authId, inviteToken)), any());
    }

}
