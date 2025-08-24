package com.example.authenticationService.service;

import com.example.authenticationService.dto.AuthorizationResponse;
import com.example.authenticationService.dto.SignupRequest;
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

    public AuthorizationResponse signup(SignupRequest request) {
        // Check if username/email already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            return new AuthorizationResponse("Username Already Taken");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return new AuthorizationResponse("Email Already Taken");
        }

        // Create User
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);

        return new AuthorizationResponse("User Registered Successfully");
    }
}
