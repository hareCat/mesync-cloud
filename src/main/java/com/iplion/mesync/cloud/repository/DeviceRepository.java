package com.iplion.mesync.cloud.repository;

import com.iplion.mesync.cloud.entity.Device;
import com.iplion.mesync.cloud.model.DeviceAuthProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {
    Optional<Device> findByUserIdAndPublicId(
        Long userId,
        UUID publicId
    );

    @Query("""
            select
                d.id as id,
                d.publicId as publicId,
                d.user.id as userId,
                d.user.authId as userAuthId,
                d.deviceType as deviceType,
                d.publicKeyBytes as publicKeyBytes,
                d.user.keyVersion as userKeyVersion
            from Device d
            where d.publicId = :publicId
              and d.revokedAt is null
        """)
    Optional<DeviceAuthProjection> findAuthDataByPublicId(UUID publicId);

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

    @Modifying
    @Query(value = """
        INSERT INTO devices (
            public_id,
            user_id,
            device_type,
            name,
            public_key_bytes,
            key_created_at,
            last_active_at,
            extras
        )
        VALUES (
            :publicId,
            :userId,
            :deviceType,
            :name,
            :publicKey,
            :keyCreatedAt,
            :lastActiveAt,
            cast(:extras as jsonb)
        )
        ON CONFLICT (user_id, name) WHERE revoked_at IS NULL
        DO NOTHING
        """, nativeQuery = true)
    int trySave(
        UUID publicId,
        Long userId,
        String deviceType,
        String name,
        byte[] publicKey,
        Instant keyCreatedAt,
        Instant lastActiveAt,
        String extras
    );

}
