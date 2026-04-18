package com.iplion.mesync.cloud.entity;

import com.iplion.mesync.cloud.model.DeviceType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Getter
@Setter
@Table(name = "devices")
public class Device {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, updatable = false)
    private UUID publicId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "device_type", nullable = false, updatable = false)
    @Enumerated(EnumType.STRING)
    private DeviceType deviceType;

    @Column(name = "name", nullable = false)
    private String name;

    //security
    @Column(name = "public_key", nullable = false, unique = true)
    private byte[] publicKey;

    @Column(name = "key_created_at", nullable = false)
    private Instant keyCreatedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt = null;

    //datetime
    @Column(name = "created_at", insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", insertable = false, updatable = false)
    private Instant updatedAt;

    @Column(name = "last_active_at", nullable = false)
    private Instant lastActiveAt = Instant.now();

    //extra
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "extras", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> extras = new HashMap<>();
}
