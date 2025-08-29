package com.example.authenticationService.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    private final JavaMailSender mailSender;

    public MailService(JavaMailSender mailSender) { this.mailSender = mailSender; }

    public void sendOtpEmail(String to, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject("Account Activation");
        msg.setText("Your verification code is: " + code + "\nThis code expires in 10 minutes.");
        mailSender.send(msg);
    }
}

