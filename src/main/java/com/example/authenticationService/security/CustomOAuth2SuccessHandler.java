package com.example.authenticationService.security;

import com.example.authenticationService.model.User;
import com.example.authenticationService.service.AuthServiceImpl;
import com.example.authenticationService.service.UserServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.example.authenticationService.common.constants.StringsGlobal.Auth.SIGNUP_GOOGLE_NO_MAIL;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserServiceImpl userServiceImpl;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthServiceImpl authServiceImpl;

    @Value("${app.frontend.success-url}")
    private String frontendSuccessUrl;

    public CustomOAuth2SuccessHandler(UserServiceImpl userServiceImpl, JwtTokenProvider jwtTokenProvider, AuthServiceImpl authServiceImpl) {
        this.userServiceImpl = userServiceImpl;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authServiceImpl = authServiceImpl;
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
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, SIGNUP_GOOGLE_NO_MAIL);
            return;
        }

        // Find Existing User or Register New One
        User user = authServiceImpl.findByEmail(email)
                .orElseGet(() -> authServiceImpl.registerGoogleUser(email, firstName, lastName));

        // Generate JWT Using the Provider
        String jwt = jwtTokenProvider.generateToken(user.getUsername());

        // Redirect to Frontend with Token
        response.sendRedirect(frontendSuccessUrl + jwt);
    }
}
