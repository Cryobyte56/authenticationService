package com.example.authenticationService.service;

import com.example.authenticationService.dto.SignupRequest;
import com.example.authenticationService.dto.SignupResponse;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public SignupResponse signup(SignupRequest request) {
        // Check if username/email already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            return new SignupResponse("Username already taken");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return new SignupResponse("Email already taken");
        }

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);

        return new SignupResponse("User registered successfully");
    }
}
