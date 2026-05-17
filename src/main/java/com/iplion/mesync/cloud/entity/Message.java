package com.iplion.mesync.cloud.entity;

import com.iplion.mesync.cloud.model.MessageDirection;
import com.iplion.mesync.cloud.model.MessageType;
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

import java.time.Instant;

//TODO add MMS
@Entity
@Getter
@Setter
@Table(name = "messages")
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", updatable = false)
    private Device device;

    @Column(name = "address", nullable = false, updatable = false)
    private String address;

    @Enumerated(EnumType.STRING)
    @Column(name = "message_type", nullable = false, updatable = false)
    private MessageType messageType;

    @Enumerated(EnumType.STRING)
    @Column(name = "direction", nullable = false, updatable = false)
    private MessageDirection direction;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(name = "created_at", insertable = false, nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "key_version", nullable = false, updatable = false)
    private Integer keyVersion;

    @Column(name = "ciphertext", nullable = false, updatable = false)
    private byte[] ciphertext;

}
