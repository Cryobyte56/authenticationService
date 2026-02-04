package com.example.authenticationService.service;

import com.example.authenticationService.dto.request.LoginRequest;
import com.example.authenticationService.dto.request.ResendOtpRequest;
import com.example.authenticationService.dto.request.SignupRequest;
import com.example.authenticationService.dto.request.VerifyOtpRequest;
import com.example.authenticationService.model.User;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.Optional;

public interface AuthService {

    public Optional<User> findByEmail(String email);
    public void signupValidate(SignupRequest request);
    public void signupSave(SignupRequest request);

    public String login(LoginRequest request);
    public Map<String, Object> getCurrentUser(Authentication authentication);
    public void logout();

    //Google
    public String getGoogleAuthRedirectUrl();
    public User registerGoogleUser(String email, String firstName, String lastName);
}
