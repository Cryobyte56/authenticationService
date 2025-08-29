package com.example.authenticationService.controller;

import com.example.authenticationService.dto.*;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import com.example.authenticationService.security.JwtTokenProvider;
import com.example.authenticationService.service.OtpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Optional;

import static com.example.authenticationService.security.JwtTokenProvider.generateToken;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtTokenProvider jwtTokenProvider;

    private final OtpService otpService;

    //-----------------------------SIGN-UP-----------------------------//

    //Sign-Up
    @PostMapping("/signup")
    public ResponseEntity<AuthorizationResponse> signup(@Validated @RequestBody SignupRequest request) {

        // Duplicate Checker
        if (userRepository.existsByUsername(request.getUsername())) {
            AuthorizationResponse response = new AuthorizationResponse("Username Already Exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            AuthorizationResponse response = new AuthorizationResponse("Email Already Exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        // Create User
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setStatus(User.UserStatus.PENDING);

        userRepository.save(user);

        otpService.createAndSendSignupOtp(user);

        AuthorizationResponse response = new AuthorizationResponse("User Registered. Verification Email Sent!");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthorizationResponse> verifyOtp(@Validated @RequestBody VerifyOtpRequest req) {
        User email = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found"));

        if (email.getStatus() == User.UserStatus.ACTIVE) {
            return ResponseEntity.ok(new AuthorizationResponse("Already verified."));
        }

        otpService.verifySignupOtp(email, req.getCode());
        return ResponseEntity.ok(new AuthorizationResponse("Email verified. Account activated."));
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<AuthorizationResponse> resendOtp(@Validated @RequestBody ResendOtpRequest req) {
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User Not Found"));

        if (user.getStatus() == User.UserStatus.ACTIVE) {
            return ResponseEntity.badRequest().body(new AuthorizationResponse("User is Already Verified."));
        }

        otpService.resendSignupOtp(user);
        return ResponseEntity.ok(new AuthorizationResponse("Verification Code Re-Sent."));
    }


    //-----------------------------LOGIN-----------------------------//

    // Login Endpoint
    @PostMapping("/login")
    public ResponseEntity<AuthorizationResponse> login(@Validated @RequestBody LoginRequest request) {
        final String invalidMsg = "Invalid Username or Password";

        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthorizationResponse(invalidMsg));
        }

        User user = userOpt.get();

        // Wrong Password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthorizationResponse(invalidMsg));
        }

        //Forbid Users That Ain't Active
        if (user.getStatus() == User.UserStatus.SUSPENDED) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new AuthorizationResponse("Account is Suspended"));
        }
        if (user.getStatus() == User.UserStatus.PENDING) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new AuthorizationResponse("Account is not yet activated"));
        }

        // Success
        String token = generateToken(user.getUsername());
        return ResponseEntity.ok(new AuthorizationResponse("Login Successful", token));
    }

    //Authenticated User Endpoint to Return Username, Email, First Name, and Last Name
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {

        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        //Return Username and Email
        return ResponseEntity.ok(Map.of(
                "username", user.getUsername(),
                "email", user.getEmail(),
                "firstName", user.getFirstName(),
                "lastName", user.getLastName()
        ));
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
