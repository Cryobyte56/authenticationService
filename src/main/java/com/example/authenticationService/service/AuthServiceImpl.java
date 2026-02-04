package com.example.authenticationService.service;

import com.example.authenticationService.dto.request.LoginRequest;
import com.example.authenticationService.dto.request.SignupRequest;
import com.example.authenticationService.model.AuthProvider;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import com.example.authenticationService.security.JwtTokenProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.*;
import static com.example.authenticationService.common.constants.StringsGlobal.UserStatus.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Commons.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final OtpServiceImpl otpServiceImpl;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder,
                           OtpServiceImpl otpServiceImpl, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpServiceImpl = otpServiceImpl;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    //Encode User's Password
    public User passwordEncoder(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        return userRepository.save(user);
    }

    // Find User by Email (For Google Login)
    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    //Sign-Up
    @Override
    public void signupValidate(SignupRequest request) {
        // Validation inputs
        // Duplicate checks
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException(SIGNUP_USERNAME_TAKEN);
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException(SIGNUP_EMAIL_TAKEN);
        }

        signupSave(request);
    }

    @Transactional
    @Override
    public void signupSave(SignupRequest request) {
        // Create user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setStatus(User.UserStatus.PENDING);
        user.setProvider(AuthProvider.LOCAL);

        // Save user
        User savedUser = userRepository.save(user);

        // Trigger OTP flow
        otpServiceImpl.createAndSendSignupOtp(savedUser);
    }

    //Login
    @Override
    public String login(LoginRequest request) {
        final String invalidMsg = LOGIN_INVALID_CREDENTIALS;

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException(invalidMsg));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException(invalidMsg);
        }

        // Check status
        if (user.getStatus() == User.UserStatus.SUSPENDED) {
            throw new IllegalStateException(LOGIN_ACCOUNT_SUSPENDED);
        }
        if (user.getStatus() == User.UserStatus.PENDING) {
            throw new IllegalStateException(LOGIN_ACCOUNT_INACTIVE);
        }

        // Return JWT
        return jwtTokenProvider.generateToken(user.getUsername());
    }

    //Get Current User
    @Override
    public Map<String, Object> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UsernameNotFoundException(LOGIN_USER_NOT_FOUND);
        }

        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(LOGIN_USER_NOT_FOUND));

        // Only return data needed at API level; leave entity-specific stuff internal
        return Map.of(
                "username", user.getUsername(),
                "email", user.getEmail(),
                "firstName", user.getFirstName(),
                "lastName", user.getLastName()
        );
    }

    //Logout
    @Override
    public void logout() {
        SecurityContextHolder.clearContext();
    }

    //Google OAuth
    @Value("${app.auth.google.authorization-uri}")
    private String googleAuthAuthorizationUri;

    @Override
    public String getGoogleAuthRedirectUrl() {
        return googleAuthAuthorizationUri;
    }

    @Transactional
    @Override
    public User registerGoogleUser(String email, String firstName, String lastName) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;

        // If Username already exists, append number.
        // This is because 2 emails might have the same email but with different domain (@gmail || @yahoo)
        while (userRepository.existsByUsername(username)) {
            username = baseUsername + counter++;
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString())); // Dummy Password
        user.setStatus(User.UserStatus.ACTIVE);
        user.setEmailVerifiedAt(Instant.now()); // Mark Active
        user.setProvider(AuthProvider.GOOGLE);  // Distinguish provider
        return userRepository.save(user);
    }
}

//TODO: Finalize AuthService and check App Properties
