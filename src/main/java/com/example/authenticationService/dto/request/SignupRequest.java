package com.example.authenticationService.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.*;

@Data
public class SignupRequest {

    @NotBlank(message = SIGNUP_FNAME_REQ)
    private String firstName;

    @NotBlank(message = SIGNUP_LNAME_REQ)
    private String lastName;

    @NotBlank(message = SIGNUP_UNAME_REQ)
    private String username;

    @Email(message = SIGNUP_INV_EMAIL)
    @NotBlank(message = SIGNUP_EMAIL_REQ)
    private String email;

    @NotBlank(message = PASS_REQUIRED)
    @Size(min = 8, message = "{auth.signup.pass.length}")
    private String password;
}
