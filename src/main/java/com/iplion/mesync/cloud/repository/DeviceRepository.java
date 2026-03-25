package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {
    boolean existsByUserAndName(User user, String name);

    @Query("""
        select count(d) > 0
        from Device d
        where d.user = :user
        and d.revokedAt is null
        """)
    boolean existsActiveByUser(User user);

    @Query("""
            select d.publicKey 
            from Device d 
            where d.publicId = :deviceId 
            and d.revokedAt is null
        """)
    Optional<byte[]> findActivePublicKeyByPublicId(UUID deviceId);
}
