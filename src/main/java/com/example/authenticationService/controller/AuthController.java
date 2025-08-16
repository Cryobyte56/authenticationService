package com.example.authenticationService.controller;

import com.example.authenticationService.dto.*;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import com.example.authenticationService.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

import static com.example.authenticationService.security.JwtTokenProvider.generateToken;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    //Sign-Up
    @PostMapping("/signup")
    public AuthorizationResponse signup(@Validated @RequestBody SignupRequest request) {

        // Duplicate Checker
        if (userRepository.existsByUsername(request.getUsername())) {
            return new AuthorizationResponse("Username Already Exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return new AuthorizationResponse("Email Already Exists");
        }

        // Create User
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

        return new AuthorizationResponse("User Registered Successfully!");
    }

    //Login
    @PostMapping("/login")
    public AuthorizationResponse login(@Validated @RequestBody LoginRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
        if (userOpt.isEmpty()) {
            return new AuthorizationResponse("Invalid Username or Password");
        }

        User user = userOpt.get();

        //Incorrect Password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return new AuthorizationResponse("Invalid Username or Password");
        }

        //Generate Token and Get the Username
        String token = generateToken(user.getUsername());

        return new AuthorizationResponse("Login Successful!", token, user.getUsername());
    }

    //Logout
    @PostMapping("/auth/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        // Optional: you can clear the security context
        SecurityContextHolder.clearContext();

        // Client should remove the JWT
        return ResponseEntity.ok("Logged Out Successfully.");
    }

}
