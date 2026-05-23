package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Message;
import com.iplion.mesync.cloud.model.SyncMessageDto;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    @Query(value = """
            select new com.iplion.mesync.cloud.model.SyncMessageDto(
                m.id,
                m.publicId,
                d.publicId,
                m.address,
                m.messageType,
                m.direction,
                m.occurredAt,
                m.keyVersion,
                m.ciphertext
            )
            from Message m
            left join m.device d
            where m.user.id = :userId
              and m.id > :afterId
              and (
                    m.device is null
                    or m.device.id != :deviceId
              )
            order by m.id
        """)
    List<SyncMessageDto> findNextAfterId(
        Long userId,
        Long deviceId,
        Long afterId,
        Pageable pageable
    );

}
