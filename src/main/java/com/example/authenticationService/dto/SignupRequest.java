package com.example.authenticationService.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {

    @NotBlank(message = "Username is Required")
    private String username;

    @Email(message = "Invalid Email Format")
    @NotBlank(message = "Email is Required")
    private String email;

    @NotBlank(message = "Password is Required")
    @Size(min = 8, message = "Password Must be at Least 8 Characters")
    private String password;
}
