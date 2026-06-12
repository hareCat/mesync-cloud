package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.config.PostgresContainerConfig;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.cache.AuthDataProjection;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Import(PostgresContainerConfig.class)
public class DeviceRepositoryTest {
    @Autowired
    DeviceRepository deviceRepository;

    @Autowired
    TestEntityManager em;

    @Test
    void findAuthContextByPublicId_shouldReturnProjection_whenDeviceActive() throws Exception {
        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device device = TestModelFactory.device(user);
        em.persistAndFlush(device);

        em.clear();

        AuthDataProjection authData = deviceRepository.findAuthContextByPublicId(device.getPublicId())
            .orElseThrow();

        assertThat(authData.getDevicePublicId()).isEqualTo(device.getPublicId());
        assertThat(authData.getUserId()).isEqualTo(user.getId());
        assertThat(authData.getUserAuthId()).isEqualTo(user.getAuthId());
        assertThat(authData.getDeviceType()).isEqualTo(device.getDeviceType());
        assertThat(authData.getPublicKeyBytes()).isEqualTo(device.getPublicKeyBytes());
    }

    @Test
    void findAuthContextByPublicId_shouldReturnEmpty_whenDeviceRevoked() throws Exception {
        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device device = TestModelFactory.device(user);
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);

        em.clear();

        Optional<AuthDataProjection> authData = deviceRepository.findAuthContextByPublicId(device.getPublicId());

        assertThat(authData).isEmpty();
    }

    @Test
    void findAuthContextByPublicId_shouldReturnEmpty_whenDeviceNotExists() {
        Optional<AuthDataProjection> authData = deviceRepository.findAuthContextByPublicId(UUID.randomUUID());

        assertThat(authData).isEmpty();
    }

    @Test
    void findActiveByUserAuthId_shouldReturnOnlyActiveDevices() throws NoSuchAlgorithmException {
        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device active = TestModelFactory.device(user, "active-device");
        em.persistAndFlush(active);

        Device revoked = TestModelFactory.device(user, "revoked-device");
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
        User user1 = TestModelFactory.user();
        User user2 = TestModelFactory.user();
        em.persistAndFlush(user1);
        em.persistAndFlush(user2);

        Device device1 = TestModelFactory.device(user1, "user1-device");
        Device device2 = TestModelFactory.device(user2, "user2-device");
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

        User user = TestModelFactory.user();
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

        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device device = TestModelFactory.device(user, deviceName);
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

        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device device = TestModelFactory.device(user, deviceName);
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
        User user = TestModelFactory.user();
        em.persistAndFlush(user);

        Device device = TestModelFactory.device(user, "test");
        device.setRevokedAt(Instant.now());
        em.persistAndFlush(device);

        boolean exists = deviceRepository.existsActiveByUserAuthId(user.getAuthId());

        assertThat(exists).isFalse();
    }

}
