package com.example.authenticationService.service;

import com.example.authenticationService.dto.request.ResendOtpRequest;
import com.example.authenticationService.dto.request.VerifyOtpRequest;
import com.example.authenticationService.model.OtpPurpose;
import com.example.authenticationService.model.OtpToken;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.OtpTokenRepository;
import com.example.authenticationService.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Commons.*;

@Service
public class OtpServiceImpl implements OtpService {
    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(10);
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(60);

    private final SecureRandom random = new SecureRandom();
    private final OtpTokenRepository otpRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailServiceImpl mailServiceImpl;
    private final UserRepository userRepository;

    public OtpServiceImpl(OtpTokenRepository otpRepo,
                          PasswordEncoder passwordEncoder,
                          MailServiceImpl mailServiceImpl, UserRepository userRepository) {
        this.otpRepo = otpRepo;
        this.passwordEncoder = passwordEncoder;
        this.mailServiceImpl = mailServiceImpl;
        this.userRepository = userRepository;
    }

    @Transactional
    @Override
    public void verifyOtp(VerifyOtpRequest req) {
        verifyOtp(req.getEmail(), req.getCode());
    }

    public void verifyOtp(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException(EMAIL_NT_FND));

        if (user.getStatus() == User.UserStatus.ACTIVE) {
            throw new IllegalStateException(SIGNUP_ALR_VERIF);
        }

        verifySignupOtp(user, code);

        user.setStatus(User.UserStatus.ACTIVE);
        userRepository.save(user);
    }

    @Transactional
    @Override
    public void createAndSendSignupOtp(User user) {
        // Throttle resends: if latest unconsumed exists and < 60s since last send, reject
        otpRepo.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(user.getId(), OtpPurpose.SIGNUP)
                .ifPresent(latest -> {
                    if (Duration.between(latest.getLastSentAt(), Instant.now()).compareTo(RESEND_COOLDOWN) < 0) {
                        throw new IllegalStateException(SIGNUP_RESEND_CD);
                    }
                });

        String code = generateNumericCode();
        String hash = passwordEncoder.encode(code);

        // Remove unconsumed tokens
        otpRepo.consumeAllForUser(user.getId(), OtpPurpose.SIGNUP, Instant.now());

        OtpToken token = new OtpToken();
        token.setUser(user);
        token.setOtpHash(hash);
        token.setPurpose(OtpPurpose.SIGNUP);
        token.setExpiresAt(Instant.now().plus(OTP_TTL));
        token.setLastSentAt(Instant.now());
        otpRepo.save(token);

        // DEV NOTE: do NOT log the code in prod. For Postman-only testing.
        mailServiceImpl.sendOtpEmail(user.getEmail(), code);
    }

    @Transactional
    @Override
    public void resendSignupOtp(ResendOtpRequest req) {
        String email = req.getEmail();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException(EMAIL_NT_FND));

        if (user.getStatus() == User.UserStatus.ACTIVE) {
            throw new IllegalStateException(SIGNUP_ALR_VERIF);
        }

        var existing = otpRepo
                .findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(user.getId(), OtpPurpose.SIGNUP);

        if (existing.isPresent()) {
            OtpToken t = existing.get();
            if (Duration.between(t.getLastSentAt(), Instant.now()).compareTo(RESEND_COOLDOWN) < 0) {
                throw new IllegalStateException(SIGNUP_RESEND_CD);
            }
        }

        createAndSendSignupOtp(user);
    }


    @Transactional
    @Override
    public void verifySignupOtp(User email, String code) {
        OtpToken token = otpRepo.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email.getId(), OtpPurpose.SIGNUP)
                .orElseThrow(() -> new IllegalArgumentException(NOPEND_VERIF));

        if (token.getConsumedAt() != null) throw new IllegalStateException(CODE_ALR_USED);
        if (Instant.now().isAfter(token.getExpiresAt())) throw new IllegalStateException(CODE_EXP);

        if (token.getAttempts() >= MAX_ATTEMPTS) throw new IllegalStateException(SIGNUP_TOO_MANY_ATT);

        // Increment Attempts
        token.setAttempts(token.getAttempts() + 1);

        if (!passwordEncoder.matches(code, token.getOtpHash())) {
            otpRepo.save(token);
            throw new IllegalArgumentException(ERR_INV_CODE);
        }

        // SUCCESS: Consume Token and Activate User
        token.setConsumedAt(Instant.now());
        otpRepo.save(token);

        email.setStatus(User.UserStatus.ACTIVE);
        email.setEmailVerifiedAt(Instant.now());
    }

    private String generateNumericCode() {
        // 000000–999999 With Leading Zeros
        int num = random.nextInt(1_000_000);
        return String.format("%06d", num);
    }
}

