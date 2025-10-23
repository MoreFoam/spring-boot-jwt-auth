package org.foam.springbootjwtauth.controller.auth;

import org.foam.springbootjwtauth.annotation.LogMethod;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.LogoutRequest;
import org.foam.springbootjwtauth.model.request.auth.RefreshRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.model.response.auth.RefreshResponse;
import org.foam.springbootjwtauth.service.auth.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @LogMethod
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse loginResponse = authService.login(loginRequest);

            return ResponseEntity.ok().body(loginResponse);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @LogMethod
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest logoutRequest) {
        authService.logout(logoutRequest);
        return ResponseEntity.ok().build();
    }

    @LogMethod
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok().body(authService.refresh(refreshRequest));
    }
}
