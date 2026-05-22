package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.model.DeviceNotificationType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeviceNotificationService {
    //TODO implement FCM
    public void notifyUserDevices(Long userId, Long excludeDeviceId, DeviceNotificationType notificationType) {
        return;
    }
}
