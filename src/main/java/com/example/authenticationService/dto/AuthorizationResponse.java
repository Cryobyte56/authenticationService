package com.example.authenticationService.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthorizationResponse {
    private String message;

    //For Login
    private String token;
    private String username;

    public AuthorizationResponse(String message) {
        this.message = message;
    }
}
