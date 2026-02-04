package com.example.authenticationService.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Locale;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.*;
import static com.example.authenticationService.common.constants.StringsGlobal.UserStatus.*;
import static com.example.authenticationService.common.constants.StringsGlobal.Commons.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {

    private final JavaMailSender mailSender;
    private final MessageSource messageSource;

    //From App Properties
    @Value("${auth.otp.expiration-minutes:10}")
    private long defaultOtpExpirationMinutes;

    @Override
    public void sendOtpEmail(String to, String code) {
        sendOtpEmail(to, code, Duration.ofMinutes(defaultOtpExpirationMinutes));
    }

    @Override
    public void sendOtpEmail(String to, String code, Duration ttl) {
        Locale locale = LocaleContextHolder.getLocale();

        String subject = messageSource.getMessage(
                "auth.signup.activation.subject",
                null,
                locale
        );

        Object[] bodyArgs = {
                code,
                ttl.toMinutes()
        };

        String text = messageSource.getMessage(
                "auth.signup.verif.code",
                bodyArgs,
                locale
        );

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(text);

        try {
            mailSender.send(msg);
            log.info("OTP email sent to {}", to);
        } catch (MailException ex) {
            log.error("Failed to send OTP email to {}", to, ex);
            throw new IllegalStateException(SIGNUP_OTP_FAILED_SEND);
        }
    }
}
