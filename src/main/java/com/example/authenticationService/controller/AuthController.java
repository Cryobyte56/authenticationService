package com.example.authenticationService.controller;

import com.example.authenticationService.dto.*;
import com.example.authenticationService.model.User;
import com.example.authenticationService.repository.UserRepository;
import com.example.authenticationService.service.OtpService;
import com.example.authenticationService.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Map;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final OtpService otpService;


    //-----------------------------SIGN-UP-----------------------------//

    //Sign-Up
    @PostMapping("/signup")
    public ResponseEntity<AuthorizationResponse> signup(@Validated @RequestBody SignupRequest request) {
        try {
            userService.registerLocalUser(request);
            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(new AuthorizationResponse("User Registered. Verification Email Sent!"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(new AuthorizationResponse(e.getMessage()));
        }
    }


    //-----------------------------OTP VERIFICATION-----------------------------//

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthorizationResponse> verifyOtp(@Validated @RequestBody VerifyOtpRequest req) {
        try {
            otpService.verifyOtp(req.getEmail(), req.getCode());
            return ResponseEntity.ok(new AuthorizationResponse("Email verified. Account activated."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new AuthorizationResponse(e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.ok(new AuthorizationResponse(e.getMessage())); // "Already Verified."
        }
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
        try {
            String token = userService.login(request);
            return ResponseEntity.ok(new AuthorizationResponse("Login Successful", token));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthorizationResponse(e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new AuthorizationResponse(e.getMessage()));
        }
    }

    //Authenticated User Endpoint to Return Username, Email, First Name, and Last Name
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {

        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found"));

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
        // Optional: Clear the Security Context
        SecurityContextHolder.clearContext();

        // Client Should Remove the JWT
        return ResponseEntity.ok("Logged Out Successfully.");
    }


    //-----------------------------GOOGLE OAUTH-----------------------------//

    //Google Login Endpoint (Hit This Endpoint For Google OAuth 2.0)
    @GetMapping("/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }

}
