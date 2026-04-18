package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Device;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {
    @Query("""
            select d.publicKey
            from Device d
            where d.publicId = :deviceId
            and d.revokedAt is null
        """)
    Optional<byte[]> findActivePublicKeyByPublicId(UUID deviceId);

    @Query("""
            select d
            from Device d
            where d.user.authId = :authId
            and d.revokedAt is null
        """)
    List<Device> findActiveByUserAuthId(UUID authId);

    @Query("""
            select count(d) > 0
            from Device d
            where d.user.authId = :authId
            and d.revokedAt is null
        """)
    boolean existsActiveByUserAuthId(UUID authId);
}
