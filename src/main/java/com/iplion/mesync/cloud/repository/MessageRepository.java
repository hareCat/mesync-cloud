package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Message;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findByUserIdAndIdGreaterThanOrderById(
        Long userId,
        Long cursor,
        Pageable pageable
    );

}
