package com.iplion.mesync.cloud.listener;

import com.iplion.mesync.cloud.config.AppProperties;
import com.iplion.mesync.cloud.error.RedisOperationException;
import com.iplion.mesync.cloud.event.DeviceRevokedEvent;
import com.iplion.mesync.cloud.security.redis.RedisKeys;
import com.iplion.mesync.cloud.security.redis.RedisSecurityStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class DeviceEventListener {
    private final RedisSecurityStore redisSecurityStore;
    private final AppProperties appProperties;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void deviceRevoked(DeviceRevokedEvent event) {
        try {
            redisSecurityStore.set(
                RedisKeys.authDeviceRevokedKey(event.targetDevicePublicId()),
                true,
                appProperties.revokeTtl()
            );
        } catch (RedisOperationException e) {
            log.warn(
                "Failed to cache revoked device {} in Redis",
                event.targetDevicePublicId(),
                e
            );
        }
    }

}
