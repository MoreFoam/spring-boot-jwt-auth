package org.foam.springbootjwtauth.controller.auth;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.foam.springbootjwtauth.annotation.LogMethod;
import org.foam.springbootjwtauth.config.RefreshCookieProperties;
import org.foam.springbootjwtauth.exception.auth.RefreshTokenNotFoundException;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.LogoutRequest;
import org.foam.springbootjwtauth.model.request.auth.RefreshRequest;
import org.foam.springbootjwtauth.model.request.auth.WebSessionRequest;
import org.foam.springbootjwtauth.model.response.auth.CsrfResponse;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.model.response.auth.RefreshResponse;
import org.foam.springbootjwtauth.model.response.auth.WebLoginResponse;
import org.foam.springbootjwtauth.model.response.auth.WebRefreshResponse;
import org.foam.springbootjwtauth.service.auth.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.NoSuchElementException;

@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {

    private final AuthService authService;
    private final RefreshCookieProperties refreshCookieProperties;

    @Autowired
    public AuthController(AuthService authService, RefreshCookieProperties refreshCookieProperties) {
        this.authService = authService;
        this.refreshCookieProperties = refreshCookieProperties;
    }

    @LogMethod
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse loginResponse = authService.login(loginRequest);

            return ResponseEntity.ok().body(loginResponse);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @LogMethod
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequest logoutRequest) {
        authService.logout(logoutRequest);
        return ResponseEntity.ok().build();
    }

    @LogMethod
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok().body(authService.refresh(refreshRequest));
    }

    @LogMethod
    @PostMapping("/web/login")
    public ResponseEntity<WebLoginResponse> webLogin(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse loginResponse = authService.login(loginRequest);

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, createRefreshCookie(loginResponse.getRefreshToken()).toString())
                    .body(new WebLoginResponse(loginResponse.getAccessToken(), loginResponse.getDeviceId()));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @LogMethod
    @PostMapping("/web/refresh")
    public ResponseEntity<WebRefreshResponse> webRefresh(
            HttpServletRequest httpServletRequest,
            @Valid @RequestBody WebSessionRequest webSessionRequest) {
        String refreshToken = getRefreshTokenCookieValue(httpServletRequest);
        RefreshRequest refreshRequest = new RefreshRequest(
                refreshToken,
                webSessionRequest.username(),
                webSessionRequest.deviceId());
        RefreshResponse refreshResponse = authService.refresh(refreshRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, createRefreshCookie(refreshResponse.getRefreshToken()).toString())
                .body(new WebRefreshResponse(refreshResponse.getAccessToken()));
    }

    @LogMethod
    @PostMapping("/web/logout")
    public ResponseEntity<Void> webLogout(
            HttpServletRequest httpServletRequest,
            @Valid @RequestBody WebSessionRequest webSessionRequest) {
        String refreshToken = getRefreshTokenCookieValueOrNull(httpServletRequest);

        if (refreshToken != null) {
            try {
                authService.logout(new LogoutRequest(
                        refreshToken,
                        webSessionRequest.username(),
                        webSessionRequest.deviceId()));
            } catch (IllegalArgumentException | JwtException | RefreshTokenNotFoundException |
                     NoSuchElementException ignored) {
                // Browser logout should still clear the local cookie even if the server-side token is already invalid.
            }
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .build();
    }

    @LogMethod
    @GetMapping("/web/csrf")
    public ResponseEntity<CsrfResponse> csrf(CsrfToken token) {
        return ResponseEntity.ok(new CsrfResponse(token.getToken(), token.getHeaderName()));
    }

    private String getRefreshTokenCookieValue(HttpServletRequest httpServletRequest) {
        String refreshToken = getRefreshTokenCookieValueOrNull(httpServletRequest);

        if (refreshToken == null) {
            throw new IllegalArgumentException("Refresh token cookie is required");
        }

        return refreshToken;
    }

    private String getRefreshTokenCookieValueOrNull(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = httpServletRequest.getCookies();

        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (refreshCookieProperties.getName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private ResponseCookie createRefreshCookie(String refreshToken) {
        return ResponseCookie.from(refreshCookieProperties.getName(), refreshToken)
                .httpOnly(true)
                .secure(refreshCookieProperties.isSecure())
                .sameSite(refreshCookieProperties.getSameSite())
                .path(refreshCookieProperties.getPath())
                .maxAge(refreshCookieProperties.getMaxAgeSeconds())
                .build();
    }

    private ResponseCookie clearRefreshCookie() {
        return ResponseCookie.from(refreshCookieProperties.getName(), "")
                .httpOnly(true)
                .secure(refreshCookieProperties.isSecure())
                .sameSite(refreshCookieProperties.getSameSite())
                .path(refreshCookieProperties.getPath())
                .maxAge(0)
                .build();
    }
}
