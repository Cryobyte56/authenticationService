package com.example.authenticationService.service;

import com.example.authenticationService.dto.LoginRequest;
import com.example.authenticationService.dto.SignupRequest;
import com.example.authenticationService.model.AuthProvider;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import com.example.authenticationService.security.JwtTokenProvider;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       OtpService otpService, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpService = otpService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    //Encode User's Password
    public User signup(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        return userRepository.save(user);
    }


    //-----------------------------SIGN-UP-----------------------------//

    // Find User by Email (For Google Login)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // Register New Google User if not Found
    @Transactional
    public User registerGoogleUser(String email, String firstName, String lastName) {
        String baseUsername = email.split("@")[0];
        String username = baseUsername;
        int counter = 1;

        // If Username Already Exists, Append Number.
        // This is Because 2 Emails Might Have the Same Email but with Different Domain (@gmail || @yahoo)
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
        user.setEmailVerifiedAt(Instant.now());// Mark Active
        user.setProvider(AuthProvider.GOOGLE);  // Distinguish Provider
        return userRepository.save(user);
    }

    @Transactional
    public User registerLocalUser(SignupRequest request) {
        // Duplicate Checks
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

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
        otpService.createAndSendSignupOtp(savedUser);

        return savedUser;
    }


    //-----------------------------LOGIN-----------------------------//

    public String login(LoginRequest request) {
        final String invalidMsg = "Invalid Username or Password";

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException(invalidMsg));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException(invalidMsg);
        }

        // Check Status
        if (user.getStatus() == User.UserStatus.SUSPENDED) {
            throw new IllegalStateException("Account is Suspended");
        }
        if (user.getStatus() == User.UserStatus.PENDING) {
            throw new IllegalStateException("Account is not yet Activated");
        }

        // Return JWT
        return jwtTokenProvider.generateToken(user.getUsername());
    }

}
