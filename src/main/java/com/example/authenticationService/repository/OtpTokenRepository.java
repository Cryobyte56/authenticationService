package com.example.authenticationService.repository;

import com.example.authenticationService.model.OtpPurpose;
import com.example.authenticationService.model.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface OtpTokenRepository extends JpaRepository <OtpToken, String> {

    Optional<OtpToken> findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            Long userId, OtpPurpose purpose);

    @Modifying
    @Query("update OtpToken o set o.consumedAt = :now where o.user.id = :userId and o.purpose = :purpose and o.consumedAt is null")
    int consumeAllForUser(@Param("userId") Long userId, @Param("purpose") OtpPurpose purpose, @Param("now") Instant now);

}
