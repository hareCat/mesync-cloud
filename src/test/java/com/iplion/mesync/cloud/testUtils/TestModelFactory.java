package com.iplion.mesync.cloud.testUtils;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.repository.DeviceRepository;
import com.iplion.mesync.cloud.repository.UserRepository;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public final class TestModelFactory {
    private static final int DEFAULT_MASTER_KEY_VERSION = 1;
    private static final DeviceType DEFAULT_DEVICE_TYPE = DeviceType.MOBILE;

    public static User user() {
        return user(UUID.randomUUID());
    }

    public static User user(UUID authId) {
        User user = new User();
        user.setAuthId(authId);

        return user;
    }

    public static User saveUser(UUID authId, UserRepository userRepository) {
        User user = user(authId);
        userRepository.saveAndFlush(user);

        return user;
    }

    public static Device device(User user) throws NoSuchAlgorithmException {
        return device(user, UUID.randomUUID().toString());
    }

    public static Device device(User user, String name) throws NoSuchAlgorithmException {
        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setUser(user);
        device.setDeviceType(DEFAULT_DEVICE_TYPE);
        device.setName(name);
        device.setPublicKeyBytes(TestCrypto.generateKeyPair().getPublic().getEncoded());
        device.setKeyCreatedAt(Instant.now());

        return device;
    }

    public static Device device(
        UUID publicId,
        User user,
        DeviceType deviceType,
        String name,
        byte[] publicKeyBytes,
        Map<String, String> extras
    ) {
        Instant now = Instant.now();

        Device device = new Device();
        device.setPublicId(publicId);
        device.setUser(user);
        device.setDeviceType(deviceType);
        device.setName(name);
        device.setPublicKeyBytes(publicKeyBytes);
        device.setKeyCreatedAt(now);
        device.setLastActiveAt(now);
        device.setExtras(extras);

        return device;
    }

    public static Device saveDevice(
        UUID publicId,
        User user,
        DeviceType deviceType,
        String name,
        byte[] publicKeyBytes,
        Map<String, String> extras,
        DeviceRepository deviceRepository
    ) {
        Device device = device(publicId, user, deviceType, name, publicKeyBytes, extras);
        deviceRepository.saveAndFlush(device);

        return device;
    }

    public static Device saveMobileDevice(
        UUID publicId,
        User user,
        String name,
        byte[] publicKeyBytes,
        Map<String, String> extras,
        DeviceRepository deviceRepository
    ) {
        return saveDevice(publicId, user, DeviceType.MOBILE, name, publicKeyBytes, extras, deviceRepository);
    }

    public static UserAuthData userAuthData() {
        return new UserAuthData(1L, UUID.randomUUID(), DEFAULT_MASTER_KEY_VERSION);
    }

    public static DeviceAuthData deviceAuthData(UUID ownerAuthId) throws NoSuchAlgorithmException {
        return new DeviceAuthData(
            1L,
            UUID.randomUUID(),
            ownerAuthId,
            DEFAULT_DEVICE_TYPE,
            TestCrypto.generateKeyPair().getPublic()
        );
    }

    public static AuthData authData() throws NoSuchAlgorithmException {
        UserAuthData userAuthData = userAuthData();

        return new AuthData(
            userAuthData,
            deviceAuthData(userAuthData.authId())
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
        message.setOccurredAt(Instant.now());
        message.setKeyVersion(DEFAULT_MASTER_KEY_VERSION);
        message.setCiphertext(new byte[44]);

        return message;
    }

    public static String inviteToken() {
        return "ABD123";
    }

}
