package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.config.PostgresContainerConfig;
import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import com.iplion.mesync.cloud.testUtils.TestModelFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;

import java.util.List;

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
    void findNextAfterId_shouldReturnMessagesByCurrentUserAfterIdExcludingCurrentDevice() throws Exception {
        User currentUser = TestModelFactory.user();
        User anotherUser = TestModelFactory.user();
        em.persist(currentUser);
        em.persist(anotherUser);

        Device currentDevice = TestModelFactory.device(currentUser, "current");
        Device anotherDevice = TestModelFactory.device(currentUser, "another");
        Device anotherUserDevice = TestModelFactory.device(anotherUser, "another user");
        em.persist(currentDevice);
        em.persist(anotherDevice);
        em.persist(anotherUserDevice);

        em.persist(TestModelFactory.message(currentUser, currentDevice));
        em.persist(TestModelFactory.message(currentUser, anotherDevice));
        em.persist(TestModelFactory.message(anotherUser, anotherUserDevice));
        em.persist(TestModelFactory.message(currentUser, null));

        Message oldMessage = TestModelFactory.message(currentUser, currentDevice);
        em.persist(oldMessage);

        em.persist(TestModelFactory.message(currentUser, currentDevice));
        Message anotherDeviceMessage = TestModelFactory.message(currentUser, anotherDevice);
        em.persist(anotherDeviceMessage);
        em.persist(TestModelFactory.message(anotherUser, anotherUserDevice));
        Message nullDeviceMessage = TestModelFactory.message(currentUser, null);
        em.persist(nullDeviceMessage);

        em.flush();

        List<SyncMessageDto> result = messageRepository.findNextAfterIdByUserExcludingDevice(
            currentUser.getId(),
            currentDevice.getId(),
            oldMessage.getId(),
            PageRequest.of(0, 10)
        );

        assertThat(result)
            .extracting(SyncMessageDto::id, SyncMessageDto::messagePublicId, SyncMessageDto::devicePublicId)
            .containsExactly(
                tuple(anotherDeviceMessage.getId(), anotherDeviceMessage.getPublicId(), anotherDevice.getPublicId()),
                tuple(nullDeviceMessage.getId(), nullDeviceMessage.getPublicId(), null)
            );
    }

    @Test
    void findNextAfterId_shouldRespectLimit() throws Exception {
        User user = TestModelFactory.user();
        em.persist(user);

        Device currentDevice = TestModelFactory.device(user, "current");
        Device anotherDevice = TestModelFactory.device(user, "another");
        em.persist(currentDevice);
        em.persist(anotherDevice);

        Message first = TestModelFactory.message(user, anotherDevice);
        Message second = TestModelFactory.message(user, anotherDevice);
        em.persist(first);
        em.persist(second);

        em.flush();

        List<SyncMessageDto> result = messageRepository.findNextAfterIdByUserExcludingDevice(
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

//    private static class TestModelFactory {
//        static Device device(User user, String deviceName) {
//            Device device = new Device();
//            device.setPublicId(UUID.randomUUID());
//            device.setUser(user);
//            device.setDeviceType(DeviceType.MOBILE);
//            device.setName(deviceName);
//            device.setPublicKeyBytes(generatePublicKeyBytes());
//            device.setKeyCreatedAt(Instant.now());
//
//            return device;
//        }
//
//        static User user() {
//            User user = new User();
//            user.setAuthId(UUID.randomUUID());
//
//            return user;
//        }
//
//        static Message message(User user, Device device) {
//            Message message = new Message();
//            message.setPublicId(UUID.randomUUID());
//            message.setUser(user);
//            message.setDevice(device);
//            message.setAddress("+995 123 456 789");
//            message.setMessageType(MessageType.SMS);
//            message.setDirection(MessageDirection.INCOMING);
//            message.setOccurredAt(Instant.now());
//            message.setKeyVersion(1);
//            message.setCiphertext(new byte[44]);
//
//            return message;
//        }
//
//        private static byte[] generatePublicKeyBytes() {
//            byte[] publicKey = new byte[44];
//            new SecureRandom().nextBytes(publicKey);
//
//            return publicKey;
//        }

//    }

}
