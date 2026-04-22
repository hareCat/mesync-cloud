package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class DeviceRepositoryTest {
    @Autowired
    DeviceRepository deviceRepository;

    @Autowired
    TestEntityManager em;

    @Test
    void findActiveByUserAuthId_shouldReturnOnlyActiveDevices() {
        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device active = TestDataFactory.device(user, "active-device");
        em.persistAndFlush(active);

        Device revoked = TestDataFactory.device(user, "revoked-device");
        revoked.setRevokedAt(Instant.now());
        em.persistAndFlush(revoked);

        em.clear();

        List<Device> result = deviceRepository.findActiveByUserAuthId(user.getAuthId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("active-device");
        assertThat(result.get(0).getRevokedAt()).isNull();
    }

    @Test
    void findActiveByUserAuthId_shouldReturnOnlyDevicesOfGivenUser() {
        User user1 = TestDataFactory.user();
        User user2 = TestDataFactory.user();
        em.persistAndFlush(user1);
        em.persistAndFlush(user2);

        Device device1 = TestDataFactory.device(user1, "user1-device");
        Device device2 = TestDataFactory.device(user2, "user2-device");
        em.persistAndFlush(device1);
        em.persistAndFlush(device2);

        em.clear();

        List<Device> result = deviceRepository.findActiveByUserAuthId(user1.getAuthId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("user1-device");
    }

    @Test
    void trySave_shouldSaveDeviceAndReturn1() {
        String deviceName = "test device";

        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        int result = deviceRepository.trySave(
            UUID.randomUUID(),
            user.getId(),
            DeviceType.BROWSER.name(),
            deviceName,
            new byte[44],
            Instant.now(),
            Instant.now(),
            "{}"
        );

        em.clear();

        List<Device> devices = deviceRepository.findActiveByUserAuthId(user.getAuthId());

        assertThat(devices).hasSize(1);
        assertThat(devices.get(0).getName()).isEqualTo(deviceName);
        assertThat(devices.get(0).getExtras()).isNotNull();
        assertThat(result).isEqualTo(1);
    }

    @Test
    void trySave_shouldNotSaveDeviceAndReturn0_whenDeviceNameAlreadyExists() {
        String deviceName = "test device";

        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device device = TestDataFactory.device(user, deviceName);
        em.persistAndFlush(device);

        int result = deviceRepository.trySave(
            UUID.randomUUID(),
            user.getId(),
            DeviceType.BROWSER.name(),
            deviceName,
            new byte[44],
            Instant.now(),
            Instant.now(),
            "{}"
        );

        em.clear();

        List<Device> devices = deviceRepository.findActiveByUserAuthId(user.getAuthId());

        assertThat(result).isEqualTo(0);
        assertThat(devices.size()).isEqualTo(1);
    }

    @Test
    void trySave_shouldSaveDeviceAndReturn1_whenDeviceNameAlreadyExistsAndRevokedAtNotNull() {
        String deviceName = "test device";

        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device device = TestDataFactory.device(user, deviceName);
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);

        int result = deviceRepository.trySave(
            UUID.randomUUID(),
            user.getId(),
            DeviceType.BROWSER.name(),
            deviceName,
            new byte[44],
            Instant.now(),
            Instant.now(),
            "{}"
        );

        em.clear();

        List<Device> allDevices = deviceRepository.findAll();
        List<Device> activeDevices = deviceRepository.findActiveByUserAuthId(user.getAuthId());

        assertThat(result).isEqualTo(1);
        assertThat(allDevices.size()).isEqualTo(2);
        assertThat(activeDevices.size()).isEqualTo(1);
        assertThat(allDevices.get(0).getName()).isEqualTo(deviceName);
        assertThat(allDevices.get(1).getName()).isEqualTo(deviceName);
    }

    @Test
    void existsActiveByUserAuthId_shouldReturnFalse_whenOnlyRevokedDevices() {
        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device device = TestDataFactory.device(user, "test");
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);

        boolean exists = deviceRepository.existsActiveByUserAuthId(user.getAuthId());

        assertThat(exists).isFalse();
    }

    @Test
    void findActivePublicKeyByPublicId_shouldReturnPublicKey() {
        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device device = TestDataFactory.device(user, "test device");
        em.persistAndFlush(device);

        byte[] publicIdBytes = deviceRepository.findActivePublicKeyByPublicId(device.getPublicId())
            .orElseThrow();

        assertThat(publicIdBytes).isEqualTo(device.getPublicKey());
    }

    @Test
    void findActivePublicKeyByPublicId_shouldReturnEmpty_whenDeviceRevoked() {
        User user = TestDataFactory.user();
        em.persistAndFlush(user);

        Device device = TestDataFactory.device(user, "test");
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);


        var result = deviceRepository.findActivePublicKeyByPublicId(device.getPublicId());

        assertThat(result).isEmpty();
    }

    private static class TestDataFactory {
        static Device device(User user, String deviceName) {
            Device device = new Device();
            device.setPublicId(UUID.randomUUID());
            device.setUser(user);
            device.setDeviceType(DeviceType.MOBILE);
            device.setName(deviceName);
            device.setPublicKey(generatePublicKeyBytes());
            device.setKeyCreatedAt(Instant.now());

            return device;
        }

        static User user() {
            User user = new User();
            user.setAuthId(UUID.randomUUID());
            user.setCreatedAt(Instant.now());
            user.setUpdatedAt(Instant.now());

            return user;
        }

        private static byte[] generatePublicKeyBytes() {
            byte[] publicKey = new byte[44];
            new SecureRandom().nextBytes(publicKey);

            return publicKey;
        }

    }

}
