package org.foam.springbootjwtauth.unit.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import org.foam.springbootjwtauth.model.database.auth.RefreshToken;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.LogoutRequest;
import org.foam.springbootjwtauth.model.request.auth.RefreshRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.model.response.auth.RefreshResponse;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.repository.auth.UserRepository;
import org.foam.springbootjwtauth.service.auth.AuthService;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceUnitTests {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void testLogin() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("user", "password");

        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("user");

        Authentication authenticationResponse = new UsernamePasswordAuthenticationToken(mockUser, loginRequest.password());
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(authenticationResponse);

        RefreshToken savedToken = new RefreshToken();
        savedToken.setId(10L);
        savedToken.setUserId(1L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(savedToken);
        when(jwtService.generateAccessToken(mockUser)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(mockUser, 10L)).thenReturn("refresh-token");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 1L);
        map.put("deviceId", "device-123");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() + 60_000));
        Claims claims = new DefaultClaims(map);
        when(jwtService.extractAllClaims("refresh-token")).thenReturn(claims);
        when(passwordEncoder.encode("refresh-token")).thenReturn("encoded-refresh-token");

        // Act
        LoginResponse result = authService.login(loginRequest);

        // Assert
        assertEquals("access-token", result.getAccessToken());
        assertEquals("refresh-token", result.getRefreshToken());
        assertEquals("device-123", result.getDeviceId());

        // Verify
        verify(authenticationManager, times(1)).authenticate(any(Authentication.class));
        verify(jwtService, times(1)).generateAccessToken(mockUser);
        verify(jwtService, times(1)).generateRefreshToken(mockUser, 10L);
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
        verify(passwordEncoder, times(1)).encode("refresh-token");
    }

    @Test
    void testLoginAuthenticationException() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("user", "wrong-password");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        // Act & Assert
        assertThrows(BadCredentialsException.class, () -> authService.login(loginRequest));

        // Verify
        verify(authenticationManager, times(1)).authenticate(any(Authentication.class));
        verify(jwtService, never()).generateAccessToken(any());
        verify(jwtService, never()).generateRefreshToken(any(), anyLong());
    }

    @Test
    void testLogout() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 1L);
        map.put("deviceId", "device-123");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() + 60_000));

        Claims claims = new DefaultClaims(map);

        when(userRepository.findByUsername(logoutRequest.username())).thenReturn(java.util.Optional.of(user));
        when(jwtService.validateRefreshToken(logoutRequest.refreshToken(), user)).thenReturn(true);
        when(jwtService.extractAllClaims(logoutRequest.refreshToken())).thenReturn(claims);

        // Act
        authService.logout(logoutRequest);

        // Verify
        verify(userRepository, times(1)).findByUsername("user");
        verify(jwtService, times(1)).validateRefreshToken(logoutRequest.refreshToken(), user);
        verify(jwtService, times(1)).extractAllClaims(logoutRequest.refreshToken());
        verify(jwtService, times(1)).invalidateRefreshToken(10L);
    }

    @Test
    void testLogout_UserNotFound() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("refresh-token", "unknown", "device-id");

        when(userRepository.findByUsername(logoutRequest.username())).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(NoSuchElementException.class, () -> authService.logout(logoutRequest));

        // Verify
        verify(userRepository, times(1)).findByUsername("unknown");
        verify(jwtService, never()).validateRefreshToken(any(), any());
        verify(jwtService, never()).invalidateRefreshToken(anyLong());
    }

    @Test
    void testLogout_InvalidRefreshToken() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("invalid-refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        when(userRepository.findByUsername(logoutRequest.username())).thenReturn(java.util.Optional.of(user));
        when(jwtService.validateRefreshToken(logoutRequest.refreshToken(), user)).thenReturn(false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.logout(logoutRequest));
        assertEquals("Invalid refresh token", exception.getMessage());

        // Verify
        verify(userRepository, times(1)).findByUsername("user");
        verify(jwtService, times(1)).validateRefreshToken(logoutRequest.refreshToken(), user);
    }

    @Test
    void testLogout_ExpiredRefreshToken() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("expired-refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 1L);
        map.put("deviceId", "device-123");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() - 60_000));

        Claims claims = new DefaultClaims(map);

        Map<String, Object> headerMap = new HashMap<>();
        headerMap.put("alg", "HS256");
        headerMap.put("typ", "JWT");

        Header header = new DefaultHeader(headerMap);

        when(userRepository.findByUsername(logoutRequest.username())).thenReturn(java.util.Optional.of(user));
        when(jwtService.validateRefreshToken(logoutRequest.refreshToken(), user)).thenThrow(new ExpiredJwtException(header, claims, "Expired Refresh Token"));
        when(jwtService.validateExpiredRefreshToken(logoutRequest.refreshToken(), claims, user)).thenReturn(true);

        // Act
        authService.logout(logoutRequest);

        // Verify
        verify(userRepository, times(1)).findByUsername("user");
        verify(jwtService, times(1)).validateRefreshToken(logoutRequest.refreshToken(), user);
        verify(jwtService, times(1)).validateExpiredRefreshToken(logoutRequest.refreshToken(), claims, user);
        verify(jwtService, times(1)).invalidateRefreshToken(10L);
        verify(jwtService, never()).extractAllClaims(anyString());
    }

    @Test
    void testLogout_ExpiredRefreshTokenInvalid() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("expired-invalid-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 1L);
        map.put("deviceId", "device-id");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() - 60_000));

        Claims claims = new DefaultClaims(map);
        Header header = new DefaultHeader(Map.of("alg", "HS256", "typ", "JWT"));

        when(userRepository.findByUsername(logoutRequest.username())).thenReturn(Optional.of(user));
        when(jwtService.validateRefreshToken(logoutRequest.refreshToken(), user))
                .thenThrow(new ExpiredJwtException(header, claims, "Expired"));
        when(jwtService.validateExpiredRefreshToken(logoutRequest.refreshToken(), claims, user))
                .thenReturn(false); // Invalid even when expired

        // Act
        authService.logout(logoutRequest);

        // Verify
        verify(userRepository, times(1)).findByUsername("user");
        verify(jwtService, times(1)).validateRefreshToken(logoutRequest.refreshToken(), user);
        verify(jwtService, times(1)).validateExpiredRefreshToken(logoutRequest.refreshToken(), claims, user);
        verify(jwtService, never()).invalidateRefreshToken(anyLong());
        verify(jwtService, never()).extractAllClaims(anyString());
    }

    @Test
    void testRefresh() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        when(userRepository.findByUsername(refreshRequest.username())).thenReturn(Optional.of(user));
        when(jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");

        // Act
        RefreshResponse response = authService.refresh(refreshRequest);

        // Assert
        assertEquals("access-token", response.getAccessToken());

        // Verify
        verify(userRepository, times(1)).findByUsername(refreshRequest.username());
        verify(jwtService, times(1)).validateRefreshToken(refreshRequest.refreshToken(), user);
        verify(jwtService, times(1)).generateAccessToken(user);
        verify(jwtService, never()).invalidateRefreshToken(anyLong());
        verify(jwtService, never()).extractAllClaims(anyString());
    }

    @Test
    void testRefresh_UserNotFound() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("invalid-refresh-token", "user", "device-id");

        when(userRepository.findByUsername(refreshRequest.username())).thenThrow(new NoSuchElementException("User not found"));

        // Act & Assert
        NoSuchElementException exception = assertThrows(NoSuchElementException.class, () -> authService.refresh(refreshRequest));
        assertEquals("User not found", exception.getMessage());

        // Verify
        verify(userRepository, times(1)).findByUsername(refreshRequest.username());
        verify(jwtService, never()).validateRefreshToken(anyString(), any(User.class));
        verify(jwtService, never()).validateExpiredRefreshToken(anyString(), any(Claims.class), any(User.class));
        verify(jwtService, never()).invalidateRefreshToken(anyLong());
        verify(jwtService, never()).generateAccessToken(any(User.class));
    }

    @Test
    void testRefresh_InvalidRefreshToken() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("invalid-refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        when(userRepository.findByUsername(refreshRequest.username())).thenReturn(Optional.of(user));
        when(jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)).thenReturn(false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.refresh(refreshRequest));
        assertEquals("Invalid refresh token", exception.getMessage());

        // Verify
        verify(userRepository, times(1)).findByUsername(refreshRequest.username());
        verify(jwtService, times(1)).validateRefreshToken(refreshRequest.refreshToken(), user);
        verify(jwtService, never()).validateExpiredRefreshToken(anyString(), any(Claims.class), any(User.class));
        verify(jwtService, never()).generateAccessToken(user);
    }

    @Test
    void testRefresh_ExpiredRefreshToken() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("invalid-refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 1L);
        map.put("deviceId", "device-id");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() - 60_000));

        Claims claims = new DefaultClaims(map);

        when(userRepository.findByUsername(refreshRequest.username())).thenReturn(Optional.of(user));
        when(jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)).thenThrow(new ExpiredJwtException(null, claims, "Expired Refresh Token"));
        when(jwtService.validateExpiredRefreshToken(refreshRequest.refreshToken(), claims, user)).thenReturn(true);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.refresh(refreshRequest));
        assertEquals("Invalid refresh token", exception.getMessage());

        // Verify
        verify(userRepository, times(1)).findByUsername(refreshRequest.username());
        verify(jwtService, times(1)).validateRefreshToken(refreshRequest.refreshToken(), user);
        verify(jwtService, times(1)).validateExpiredRefreshToken(anyString(), any(Claims.class), any(User.class));
        verify(jwtService, times(1)).invalidateRefreshToken(anyLong());
        verify(jwtService, never()).generateAccessToken(user);
    }

    @Test
    void testRefresh_ExpiredRefreshTokenInvalid() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("invalid-refresh-token", "user", "device-id");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");

        Map<String, Object> map = new HashMap<>();
        map.put("id", 10L);
        map.put("userId", 999L); // Wrong user id
        map.put("deviceId", "wrong-device-id");
        map.put(Claims.SUBJECT, "user");
        map.put(Claims.EXPIRATION, new Date(System.currentTimeMillis() - 60_000));

        Claims claims = new DefaultClaims(map);

        when(userRepository.findByUsername(refreshRequest.username())).thenReturn(Optional.of(user));
        when(jwtService.validateRefreshToken(refreshRequest.refreshToken(), user)).thenThrow(new ExpiredJwtException(null, claims, "Expired Refresh Token"));
        when(jwtService.validateExpiredRefreshToken(refreshRequest.refreshToken(), claims, user)).thenReturn(false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.refresh(refreshRequest));
        assertEquals("Invalid refresh token", exception.getMessage());

        // Verify
        verify(userRepository, times(1)).findByUsername(refreshRequest.username());
        verify(jwtService, times(1)).validateRefreshToken(refreshRequest.refreshToken(), user);
        verify(jwtService, times(1)).validateExpiredRefreshToken(anyString(), any(Claims.class), any(User.class));
        verify(jwtService, never()).invalidateRefreshToken(anyLong());
        verify(jwtService, never()).generateAccessToken(user);
    }
}
