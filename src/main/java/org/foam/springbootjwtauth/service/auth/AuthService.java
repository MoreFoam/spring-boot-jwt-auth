package org.foam.springbootjwtauth.service.auth;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.transaction.Transactional;
import org.foam.springbootjwtauth.model.database.auth.RefreshToken;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.LogoutRequest;
import org.foam.springbootjwtauth.model.request.auth.RefreshRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.model.response.auth.RefreshResponse;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.repository.auth.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       RefreshTokenRepository refreshTokenRepository,
                       UserRepository userRepository,
                       PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) throws AuthenticationException {
        // Attempt to authenticate
        Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);
        // Get the authenticated user
        User user = (User) authenticationResponse.getPrincipal();
        // Save the refresh token to db
        RefreshToken refreshTokenObj = new RefreshToken();
        refreshTokenObj.setUserId(user.getId());
        refreshTokenObj = refreshTokenRepository.save(refreshTokenObj);
        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenObj.getId());
        // Add additional claims to entity & save
        refreshTokenObj.setToken(passwordEncoder.encode(refreshToken));
        refreshTokenObj.setDeviceId(jwtService.extractAllClaims(refreshToken).get("deviceId").toString());
        refreshTokenRepository.save(refreshTokenObj);
        // Return response
        return new LoginResponse(accessToken, refreshToken, refreshTokenObj.getDeviceId());
    }

    @Transactional
    public void logout(LogoutRequest logoutRequest) {
        // Get the user
        User user = userRepository.findByUsername(logoutRequest.username())
                .orElseThrow(() -> new NoSuchElementException("User not found"));
        // Check if the refresh token is valid. If not, invalidate it by deleting the Entity from db
        try {
            if (!jwtService.validateRefreshToken(logoutRequest.refreshToken(), user)) {
                throw new IllegalArgumentException("Invalid refresh token");
            }
        } catch (ExpiredJwtException e) { // If token is expired, we still need to validate the claims and token
            // Invalidate the refresh token, by deleting the entity if the claims and token are valid
            if (jwtService.validateExpiredRefreshToken(logoutRequest.refreshToken(), e.getClaims(), user)) {
                Long refreshTokenId = Long.valueOf(e.getClaims().get("id").toString());
                jwtService.invalidateRefreshToken(refreshTokenId);
            }

            return;
        }
        // Invalidate the refresh token by deleting the entity
        Long refreshTokenId = Long.valueOf(jwtService.extractAllClaims(logoutRequest.refreshToken()).get("id").toString());
        jwtService.invalidateRefreshToken(refreshTokenId);

        // NOTE: The access tokens are not stored in either whitelist/blacklist. This means if an access token
        // is compromised, it can be used by malicious actors until it expires (configured by
        // spring-boot-jwt-auth.security.jwt.expiration in application.properties). If needed, to make this auth
        // flow more secure, a whitelist/blacklist entity (e.g. AccessToken or RevokedAccessToken) could be created.
    }

    @Transactional
    public RefreshResponse refresh(RefreshRequest refreshRequest) {
        // Get the user
        User user = userRepository.findByUsername(refreshRequest.username())
                .orElseThrow(() -> new NoSuchElementException("User not found"));
        // Check if the refresh token is valid
        try {
            if (!jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)) {
                Long refreshTokenId = Long.valueOf(jwtService.extractAllClaims(refreshRequest.refreshToken()).get("id").toString());
                jwtService.invalidateRefreshToken(refreshTokenId);

                throw new IllegalArgumentException("Invalid refresh token");
            }
        } catch (ExpiredJwtException e) { // If token is expired, we still need to validate the claims and token
            // Delete the refresh token entity if the claims and token are valid
            if (jwtService.validateExpiredRefreshToken(refreshRequest.refreshToken(), e.getClaims(), user)) {
                Long refreshTokenId = Long.valueOf(e.getClaims().get("id").toString());
                jwtService.invalidateRefreshToken(refreshTokenId);
            }

            throw new IllegalArgumentException("Invalid refresh token");
        }

        // Return new token
        return new RefreshResponse(jwtService.generateAccessToken(user));
    }
}
