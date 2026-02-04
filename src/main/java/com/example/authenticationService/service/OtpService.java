package com.example.authenticationService.service;

import com.example.authenticationService.dto.request.ResendOtpRequest;
import com.example.authenticationService.dto.request.VerifyOtpRequest;
import com.example.authenticationService.model.User;

public interface OtpService {

    public void verifyOtp(VerifyOtpRequest req);
    public void createAndSendSignupOtp(User user);
    public void resendSignupOtp(ResendOtpRequest req);
    public void verifySignupOtp(User email, String code);
}
