package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
    void findActiveByUserAuthId_shouldReturnOnlyActiveDevices() throws Exception {
        User user = buildUser();
        em.persistAndFlush(user);

        Device active = buildDevice(user, "active-device");
        em.persistAndFlush(active);

        Device revoked = buildDevice(user, "revoked-device");
        revoked.setRevokedAt(Instant.now());
        em.persistAndFlush(revoked);

        em.clear();

        List<Device> result = deviceRepository.findActiveByUserAuthId(user.getAuthId());

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("active-device");
        assertThat(result.get(0).getRevokedAt()).isNull();
    }

    @Test
    void findActiveByUserAuthId_shouldReturnOnlyDevicesOfGivenUser() throws Exception {
        User user1 = buildUser();
        User user2 = buildUser();
        em.persistAndFlush(user1);
        em.persistAndFlush(user2);

        Device device1 = buildDevice(user1, "user1-device");
        Device device2 = buildDevice(user2, "user2-device");
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

        User user = buildUser();
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
    void trySave_shouldNotSaveDeviceAndReturn0_whenDeviceNameAlreadyExists() throws Exception {
        String deviceName = "test device";

        User user = buildUser();
        em.persistAndFlush(user);

        Device device = buildDevice(user, deviceName);
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
    void trySave_shouldSaveDeviceAndReturn1_whenDeviceNameAlreadyExistsAndRevokedAtNotNull() throws Exception {
        String deviceName = "test device";

        User user = buildUser();
        em.persistAndFlush(user);

        Device device = buildDevice(user, deviceName);
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
    void existsActiveByUserAuthId_shouldReturnFalse_whenOnlyRevokedDevices() throws Exception {
        User user = buildUser();
        em.persistAndFlush(user);

        Device device = buildDevice(user, "test");
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);

        boolean exists = deviceRepository.existsActiveByUserAuthId(user.getAuthId());

        assertThat(exists).isFalse();
    }

    @Test
    void findActivePublicKeyByPublicId_shouldReturnPublicKey() throws Exception {
        User user = buildUser();
        em.persistAndFlush(user);

        Device device = buildDevice(user, "test device");
        em.persistAndFlush(device);

        byte[] publicIdBytes = deviceRepository.findActivePublicKeyByPublicId(device.getPublicId())
            .orElseThrow();

        assertThat(publicIdBytes).isEqualTo(device.getPublicKey());
    }

    @Test
    void findActivePublicKeyByPublicId_shouldReturnEmpty_whenDeviceRevoked() throws Exception {
        User user = buildUser();
        em.persistAndFlush(user);

        Device device = buildDevice(user, "test");
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);


        var result = deviceRepository.findActivePublicKeyByPublicId(device.getPublicId());

        assertThat(result).isEmpty();
    }

    // builders

    private Device buildDevice(User user, String deviceName) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        byte[] publicKeyBytes = generator.generateKeyPair().getPublic().getEncoded();

        Device device = new Device();
        device.setPublicId(UUID.randomUUID());
        device.setUser(user);
        device.setDeviceType(DeviceType.MOBILE);
        device.setName(deviceName);
        device.setPublicKey(publicKeyBytes);
        device.setKeyCreatedAt(Instant.now());

        return device;
    }

    private User buildUser() {
        User user = new User();
        user.setAuthId(UUID.randomUUID());
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());

        return user;
    }
}
