package com.example.authenticationService.service;

import java.time.Duration;

public interface MailService {

    public void sendOtpEmail(String to, String code);
    public void sendOtpEmail(String to, String code, Duration ttl);
}
