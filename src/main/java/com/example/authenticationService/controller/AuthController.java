package com.example.authenticationService.controller;

import com.example.authenticationService.dto.LoginRequest;
import com.example.authenticationService.dto.LoginResponse;
import com.example.authenticationService.dto.SignupRequest;
import com.example.authenticationService.dto.SignupResponse;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    //Sign-Up
    @PostMapping("/signup")
    public SignupResponse signup(@RequestBody SignupRequest request) {

        // Duplicate Checker
        if (userRepository.existsByUsername(request.getUsername())) {
            return new SignupResponse("Username Already Exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return new SignupResponse("Email Already Exists");
        }

        // Create User
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

        return new SignupResponse("User registered successfully!");
    }

    //Login
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new LoginResponse("Invalid username or password");
        }

        User user = userOpt.get();

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return new LoginResponse("Invalid username or password");
        }

        return new LoginResponse("Login Successful!");
    }
}
