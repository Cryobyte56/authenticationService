package com.example.authenticationService.service;

import com.example.authenticationService.model.OtpPurpose;
import com.example.authenticationService.model.OtpToken;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.OtpTokenRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

@Service
public class OtpService {
    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(10);
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(60);

    private final SecureRandom random = new SecureRandom();
    private final OtpTokenRepository otpRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;

    public OtpService(OtpTokenRepository otpRepo,
                      PasswordEncoder passwordEncoder,
                      MailService mailService) {
        this.otpRepo = otpRepo;
        this.passwordEncoder = passwordEncoder;
        this.mailService = mailService;
    }

    @Transactional
    public void createAndSendSignupOtp(User user) {
        // Throttle resends: if latest unconsumed exists and < 60s since last send, reject
        otpRepo.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(user.getId(), OtpPurpose.SIGNUP)
                .ifPresent(latest -> {
                    if (Duration.between(latest.getLastSentAt(), Instant.now()).compareTo(RESEND_COOLDOWN) < 0) {
                        throw new IllegalStateException("Please wait before requesting another code.");
                    }
                });

        String code = generateNumericCode();
        String hash = passwordEncoder.encode(code);

        // Remove Unconsumed Tokens
        otpRepo.consumeAllForUser(user.getId(), OtpPurpose.SIGNUP, Instant.now());

        OtpToken token = new OtpToken();
        token.setUser(user);
        token.setOtpHash(hash);
        token.setPurpose(OtpPurpose.SIGNUP);
        token.setExpiresAt(Instant.now().plus(OTP_TTL));
        token.setLastSentAt(Instant.now());
        otpRepo.save(token);

        // DEV NOTE: do NOT log the code in prod. For Postman-only testing, the email is your source of truth.
        mailService.sendOtpEmail(user.getEmail(), code);
    }

    @Transactional
    public void resendSignupOtp(User user) {
        var existing = otpRepo.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(user.getId(), OtpPurpose.SIGNUP);
        if (existing.isPresent()) {
            OtpToken t = existing.get();
            if (Duration.between(t.getLastSentAt(), Instant.now()).compareTo(RESEND_COOLDOWN) < 0) {
                throw new IllegalStateException("Please wait before requesting another code.");
            }
        }
        createAndSendSignupOtp(user);
    }

    @Transactional
    public void verifySignupOtp(User email, String code) {
        OtpToken token = otpRepo.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email.getId(), OtpPurpose.SIGNUP)
                .orElseThrow(() -> new IllegalArgumentException("No Pending Verification."));

        if (token.getConsumedAt() != null) throw new IllegalStateException("Code already used.");
        if (Instant.now().isAfter(token.getExpiresAt())) throw new IllegalStateException("Code expired.");

        if (token.getAttempts() >= MAX_ATTEMPTS) throw new IllegalStateException("Too many attempts. Request a new code.");

        // increment attempts regardless of outcome
        token.setAttempts(token.getAttempts() + 1);

        if (!passwordEncoder.matches(code, token.getOtpHash())) {
            otpRepo.save(token);
            throw new IllegalArgumentException("Invalid code.");
        }

        // success: consume token + activate user
        token.setConsumedAt(Instant.now());
        otpRepo.save(token);

        email.setStatus(User.UserStatus.ACTIVE);
        email.setEmailVerifiedAt(Instant.now());
    }

    private String generateNumericCode() {
        // 000000–999999 with leading zeros
        int num = random.nextInt(1_000_000);
        return String.format("%06d", num);
    }
}

