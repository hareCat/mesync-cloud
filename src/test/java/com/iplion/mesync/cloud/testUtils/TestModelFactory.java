package com.iplion.mesync.cloud.testUtils;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;

public final class TestModelFactory {
    private static final Instant NOW = Instant.now();
    private static final int MASTER_KEY_VERSION = 1;
    private static final DeviceType DEVICE_TYPE = DeviceType.MOBILE;

    public static Device device(User user) throws NoSuchAlgorithmException {
        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setUser(user);
        device.setDeviceType(DEVICE_TYPE);
        device.setName(UUID.randomUUID().toString());
        device.setPublicKeyBytes(TestCrypto.generateKeyPair().getPublic().getEncoded());
        device.setKeyCreatedAt(NOW);

        return device;
    }

    public static User user() {
        User user = new User();
        user.setAuthId(UUID.randomUUID());

        return user;
    }

    public static AuthData authContext() throws NoSuchAlgorithmException {
        return new AuthData(
            new UserAuthData(1L, UUID.randomUUID(), MASTER_KEY_VERSION),
            new DeviceAuthData(
                1L,
                UUID.randomUUID(),
                DEVICE_TYPE,
                TestCrypto.generateKeyPair().getPublic()
            )
        );
    }

    public static Message message(User user, Device device) {
        Message message = new Message();
        message.setPublicId(UUID.randomUUID());
        message.setUser(user);
        message.setDevice(device);
        message.setAddress("+995 123 456 789");
        message.setMessageType(MessageType.SMS);
        message.setDirection(MessageDirection.INCOMING);
        message.setOccurredAt(NOW);
        message.setKeyVersion(MASTER_KEY_VERSION);
        message.setCiphertext(new byte[44]);

        return message;
    }

}
