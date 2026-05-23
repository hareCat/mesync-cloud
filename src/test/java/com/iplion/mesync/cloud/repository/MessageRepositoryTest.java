package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.config.PostgresContainerConfig;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

@DataJpaTest
@Import(PostgresContainerConfig.class)
public class MessageRepositoryTest {
    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private TestEntityManager em;

    @Test
    void findNextAfterId_shouldReturnMessagesByCurrentUserAfterIdExcludingCurrentDevice() {
        User currentUser = TestDataFactory.user();
        User anotherUser = TestDataFactory.user();
        em.persist(currentUser);
        em.persist(anotherUser);

        Device currentDevice = TestDataFactory.device(currentUser, "current");
        Device anotherDevice = TestDataFactory.device(currentUser, "another");
        Device anotherUserDevice = TestDataFactory.device(anotherUser, "another user");
        em.persist(currentDevice);
        em.persist(anotherDevice);
        em.persist(anotherUserDevice);

        em.persist(TestDataFactory.message(currentUser, currentDevice));
        em.persist(TestDataFactory.message(currentUser, anotherDevice));
        em.persist(TestDataFactory.message(anotherUser, anotherUserDevice));
        em.persist(TestDataFactory.message(currentUser, null));

        Message oldMessage = TestDataFactory.message(currentUser, currentDevice);
        em.persist(oldMessage);

        em.persist(TestDataFactory.message(currentUser, currentDevice));
        Message anotherDeviceMessage = TestDataFactory.message(currentUser, anotherDevice);
        em.persist(anotherDeviceMessage);
        em.persist(TestDataFactory.message(anotherUser, anotherUserDevice));
        Message nullDeviceMessage = TestDataFactory.message(currentUser, null);
        em.persist(nullDeviceMessage);

        em.flush();

        List<SyncMessageDto> result = messageRepository.findNextAfterId(
            currentUser.getId(),
            currentDevice.getId(),
            oldMessage.getId(),
            PageRequest.of(0, 10)
        );

        assertThat(result)
            .extracting(SyncMessageDto::id, SyncMessageDto::publicId, SyncMessageDto::devicePublicId)
            .containsExactly(
                tuple(anotherDeviceMessage.getId(), anotherDeviceMessage.getPublicId(), anotherDevice.getPublicId()),
                tuple(nullDeviceMessage.getId(), nullDeviceMessage.getPublicId(), null)
            );
    }

    @Test
    void findNextAfterId_shouldRespectLimit() {
        User user = TestDataFactory.user();
        em.persist(user);

        Device currentDevice = TestDataFactory.device(user, "current");
        Device anotherDevice = TestDataFactory.device(user, "another");
        em.persist(currentDevice);
        em.persist(anotherDevice);

        Message first = TestDataFactory.message(user, anotherDevice);
        Message second = TestDataFactory.message(user, anotherDevice);
        em.persist(first);
        em.persist(second);

        em.flush();

        List<SyncMessageDto> result = messageRepository.findNextAfterId(
                user.getId(),
                currentDevice.getId(),
                0L,
                PageRequest.of(0, 1)
            );

        assertThat(result)
            .hasSize(1)
            .extracting(SyncMessageDto::id)
            .containsExactly(first.getId());
    }

    // helpers ----------------------------------------

    private static class TestDataFactory {
        static Device device(User user, String deviceName) {
            Device device = new Device();
            device.setPublicId(UUID.randomUUID());
            device.setUser(user);
            device.setDeviceType(DeviceType.MOBILE);
            device.setName(deviceName);
            device.setPublicKeyBytes(generatePublicKeyBytes());
            device.setKeyCreatedAt(Instant.now());

            return device;
        }

        static User user() {
            User user = new User();
            user.setAuthId(UUID.randomUUID());

            return user;
        }

        static Message message(User user, Device device) {
            Message message = new Message();
            message.setPublicId(UUID.randomUUID());
            message.setUser(user);
            message.setDevice(device);
            message.setAddress("+995 123 456 789");
            message.setMessageType(MessageType.SMS);
            message.setDirection(MessageDirection.INCOMING);
            message.setOccurredAt(Instant.now());
            message.setKeyVersion(1);
            message.setCiphertext(new byte[44]);

            return message;
        }

        private static byte[] generatePublicKeyBytes() {
            byte[] publicKey = new byte[44];
            new SecureRandom().nextBytes(publicKey);

            return publicKey;
        }

    }

}
