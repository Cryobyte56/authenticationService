package com.example.authenticationService.controller;

import com.example.authenticationService.dto.request.LoginRequest;
import com.example.authenticationService.dto.request.ResendOtpRequest;
import com.example.authenticationService.dto.request.SignupRequest;
import com.example.authenticationService.dto.request.VerifyOtpRequest;
import com.example.authenticationService.dto.response.AuthorizationResponse;
import com.example.authenticationService.service.AuthService;
import com.example.authenticationService.service.AuthServiceImpl;
import com.example.authenticationService.service.OtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Commons.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final OtpService otpService;

    //Signup
    @PostMapping("/signup")
    public ResponseEntity<AuthorizationResponse> signup(@Validated @RequestBody SignupRequest request) {
        try {
            authService.signupValidate(request);
            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(new AuthorizationResponse(SIGNUP_SUCCESS));
        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(new AuthorizationResponse(e.getMessage()));
        }
    }

    //OTP Verification
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthorizationResponse> verifyOtp(@Validated @RequestBody VerifyOtpRequest req) {
        try {
            otpService.verifyOtp(req);
            return ResponseEntity.ok(new AuthorizationResponse(SIGNUP_VERIF_SUCCESS));
        } catch (IllegalArgumentException e) {
            // ex: OTP not found, invalid OTP, user not found, etc.
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new AuthorizationResponse(e.getMessage()));
        } catch (IllegalStateException e) {
            // ex: "Already Verified."
            return ResponseEntity.ok(new AuthorizationResponse(e.getMessage()));
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<AuthorizationResponse> resendOtp(@Validated @RequestBody ResendOtpRequest req) {
        try {
            otpService.resendSignupOtp(req);
            return ResponseEntity.ok(new AuthorizationResponse(SIGNUP_OTP_SENT));
        } catch (IllegalArgumentException e) {
            // User not found
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new AuthorizationResponse(e.getMessage()));
        } catch (IllegalStateException e) {
            // Verified
            return ResponseEntity.badRequest()
                    .body(new AuthorizationResponse(e.getMessage()));
        }
    }


    //Login
    @PostMapping("/login")
    public ResponseEntity<AuthorizationResponse> login(@Validated @RequestBody LoginRequest request) {
        try {
            String token = authService.login(request);
            return ResponseEntity.ok(new AuthorizationResponse(LOGIN_SUCCESS, token));
        } catch (IllegalArgumentException e) {
            // ex: invalid credentials
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthorizationResponse(e.getMessage()));
        } catch (IllegalStateException e) {
            // ex: account locked/disabled/inactive
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new AuthorizationResponse(e.getMessage()));
        }
    }

    //Get current user
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        Map<String, Object> userInfo = authService.getCurrentUser(authentication);
        return ResponseEntity.ok(userInfo);
    }

    //Logout
    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        authService.logout();
        return ResponseEntity.ok(LOGGED_OUT);
    }

    //Google OAuth
    @GetMapping("/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        String redirectUrl = authService.getGoogleAuthRedirectUrl();
        response.sendRedirect(redirectUrl);
    }
}
