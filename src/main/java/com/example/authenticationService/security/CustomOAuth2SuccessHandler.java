package com.example.authenticationService.security;

import com.example.authenticationService.model.User;
import com.example.authenticationService.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${app.frontend.success-url}")
    private String frontendSuccessUrl;

    public CustomOAuth2SuccessHandler(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("OAuth2 attributes: " + oAuth2User.getAttributes());

        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");   // First name
        String lastName = oAuth2User.getAttribute("family_name"); // Last name

        if (email == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Google Account Has No Email");
            return;
        }

        // Find Existing User or Register New One
        User user = userService.findByEmail(email)
                .orElseGet(() -> userService.registerGoogleUser(email, firstName, lastName));

        // Generate JWT Using the Provider
        String jwt = jwtTokenProvider.generateToken(user.getUsername());

        // Redirect to Frontend with Token
        response.sendRedirect(frontendSuccessUrl + jwt);
    }
}
