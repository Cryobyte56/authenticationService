package com.example.authenticationService.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name="otp_tokens", indexes = {
        @Index(name="idx_otp_user_purpose", columnList = "user_id, purpose, consumedAt, expiresAt")
})

@Data
public class OtpToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    private User user;

    // BCrypt hash of the otp
    @Column(nullable = false, length = 100)
    private String otpHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private OtpPurpose purpose = OtpPurpose.SIGNUP;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant consumedAt;

    @Column(nullable = false)
    private int attempts = 0;

    // For Re-Sending Token
    @Column(nullable = false)
    private Instant lastSentAt = Instant.now();
}