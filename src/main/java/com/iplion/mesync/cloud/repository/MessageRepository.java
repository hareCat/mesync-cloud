package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Message;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    @Query(value = """
            select *
            from messages m
            where m.user_id = :userId
              and m.id > :afterId
              and (
                    m.device_id is null
                    or m.device_id != :deviceId
              )
            order by m.id
            limit :limit
        """, nativeQuery = true)
    List<Message> findNextAfterId(
        Long userId,
        Long deviceId,
        Long afterId,
        int limit
    );

}
