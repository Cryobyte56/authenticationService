package com.example.authenticationService.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.PASS_REQUIRED;
import static com.example.authenticationService.common.constants.StringsGlobal.Auth.UNAME_REQUIRED;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = UNAME_REQUIRED)
    private String username;

    @NotBlank(message = PASS_REQUIRED)
    private String password;
}
