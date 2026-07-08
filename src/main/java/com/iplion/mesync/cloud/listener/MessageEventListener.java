package com.iplion.mesync.cloud.listener;

import com.iplion.mesync.cloud.event.MessagePublishedEvent;
import com.iplion.mesync.cloud.model.DeviceNotificationType;
import com.iplion.mesync.cloud.service.DeviceNotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
public class MessageEventListener {

    private final DeviceNotificationService deviceNotificationService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void messagePublished(MessagePublishedEvent event) {
        deviceNotificationService.notifyUserDevices(
            event.userId(),
            event.excludeDeviceId(),
            DeviceNotificationType.SYNC_REQUIRED
        );
    }
}
