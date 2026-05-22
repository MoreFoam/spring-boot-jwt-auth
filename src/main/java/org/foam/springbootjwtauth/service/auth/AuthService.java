package org.foam.springbootjwtauth.service.auth;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Claims;
import org.foam.springbootjwtauth.config.LoginLockoutProperties;
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
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuthService {

    private static final String INVALID_REFRESH_TOKEN_MESSAGE = "Invalid refresh token";

    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginLockoutProperties loginLockoutProperties;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       RefreshTokenRepository refreshTokenRepository,
                       UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       LoginLockoutProperties loginLockoutProperties) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginLockoutProperties = loginLockoutProperties;
    }

    @Transactional(noRollbackFor = AuthenticationException.class)
    public LoginResponse login(LoginRequest loginRequest) throws AuthenticationException {
        // Attempt to authenticate
        Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password());
        Authentication authenticationResponse;
        try {
            authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);
        } catch (AuthenticationException e) {
            recordFailedLoginAttempt(loginRequest.username());
            throw e;
        }

        // Get the authenticated user
        User user = (User) authenticationResponse.getPrincipal();
        resetFailedLoginAttempts(user);

        return createSession(user, null);
    }

    @Transactional
    public void logout(LogoutRequest logoutRequest) {
        // Get the user
        User user = getUserForRefreshSession(logoutRequest.username());
        // Check if the refresh token is valid. If not, invalidate it by deleting the Entity from db
        Claims claims;
        try {
            if (!jwtService.validateRefreshToken(logoutRequest.refreshToken(), user)) {
                throw invalidRefreshTokenException();
            }
            claims = jwtService.extractAllClaims(logoutRequest.refreshToken());
        } catch (ExpiredJwtException e) { // If token is expired, we still need to validate the claims and token
            // Invalidate the refresh token, by deleting the entity if the claims and token are valid
            if (jwtService.validateExpiredRefreshToken(logoutRequest.refreshToken(), e.getClaims(), user)) {
                validateDeviceId(logoutRequest.deviceId(), e.getClaims());
                Long refreshTokenId = Long.valueOf(e.getClaims().get("id").toString());
                jwtService.invalidateRefreshToken(refreshTokenId);
            }

            return;
        }

        validateDeviceId(logoutRequest.deviceId(), claims);

        // Invalidate the refresh token by deleting the entity
        Long refreshTokenId = Long.valueOf(claims.get("id").toString());
        jwtService.invalidateRefreshToken(refreshTokenId);

        // NOTE: The access tokens are not stored in either whitelist/blacklist. This means if an access token
        // is compromised, it can be used by malicious actors until it expires (configured by
        // spring-boot-jwt-auth.security.jwt.expiration in application.properties). If needed, to make this auth
        // flow more secure, a whitelist/blacklist entity (e.g. AccessToken or RevokedAccessToken) could be created.
    }

    @Transactional
    public RefreshResponse refresh(RefreshRequest refreshRequest) {
        // Get the user
        User user = getUserForRefreshSession(refreshRequest.username());
        // Check if the refresh token is valid
        Claims claims;
        try {
            if (!jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)) {
                throw invalidRefreshTokenException();
            }
            claims = jwtService.extractAllClaims(refreshRequest.refreshToken());
        } catch (ExpiredJwtException e) { // If token is expired, we still need to validate the claims and token
            // Delete the refresh token entity if the claims and token are valid
            if (jwtService.validateExpiredRefreshToken(refreshRequest.refreshToken(), e.getClaims(), user)) {
                validateDeviceId(refreshRequest.deviceId(), e.getClaims());
                Long refreshTokenId = Long.valueOf(e.getClaims().get("id").toString());
                jwtService.invalidateRefreshToken(refreshTokenId);
            }

            throw invalidRefreshTokenException();
        }

        validateDeviceId(refreshRequest.deviceId(), claims);

        Long refreshTokenId = Long.valueOf(claims.get("id").toString());
        jwtService.invalidateRefreshToken(refreshTokenId);

        LoginResponse loginResponse = createSession(user, refreshRequest.deviceId());

        return new RefreshResponse(loginResponse.getAccessToken(), loginResponse.getRefreshToken());
    }

    private LoginResponse createSession(User user, String deviceId) {
        RefreshToken refreshTokenObj = new RefreshToken();
        refreshTokenObj.setUserId(user.getId());
        refreshTokenObj = refreshTokenRepository.save(refreshTokenObj);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = deviceId == null
                ? jwtService.generateRefreshToken(user, refreshTokenObj.getId())
                : jwtService.generateRefreshToken(user, refreshTokenObj.getId(), deviceId);

        refreshTokenObj.setToken(passwordEncoder.encode(refreshToken));
        refreshTokenObj.setDeviceId(jwtService.extractAllClaims(refreshToken).get("deviceId").toString());
        refreshTokenRepository.save(refreshTokenObj);

        return new LoginResponse(accessToken, refreshToken, refreshTokenObj.getDeviceId());
    }

    private void validateDeviceId(String requestDeviceId, Claims claims) {
        if (!requestDeviceId.equals(claims.get("deviceId", String.class))) {
            throw invalidRefreshTokenException();
        }
    }

    private void recordFailedLoginAttempt(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            Instant now = Instant.now();

            if (!user.isAccountNonLocked()) {
                return;
            }

            clearExpiredTemporaryLock(user, now);
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            if (shouldTemporarilyLock(user)) {
                user.setLockedUntil(now.plus(loginLockoutProperties.getLockDuration()));
            }

            userRepository.save(user);
        });
    }

    private void resetFailedLoginAttempts(User user) {
        if (user.getFailedLoginAttempts() == 0 && user.getLockedUntil() == null) {
            return;
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }

    private void clearExpiredTemporaryLock(User user, Instant now) {
        if (user.getLockedUntil() != null && !user.getLockedUntil().isAfter(now)) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        }
    }

    private boolean shouldTemporarilyLock(User user) {
        return loginLockoutProperties.getMaxFailedAttempts() > 0
                && user.getFailedLoginAttempts() >= loginLockoutProperties.getMaxFailedAttempts();
    }

    private User getUserForRefreshSession(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(this::invalidRefreshTokenException);
    }

    private IllegalArgumentException invalidRefreshTokenException() {
        return new IllegalArgumentException(INVALID_REFRESH_TOKEN_MESSAGE);
    }
}
