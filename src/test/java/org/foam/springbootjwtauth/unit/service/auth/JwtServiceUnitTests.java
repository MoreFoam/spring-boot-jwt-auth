package org.foam.springbootjwtauth.unit.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.foam.springbootjwtauth.model.database.auth.RefreshToken;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtServiceUnitTests {

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Mock
    PasswordEncoder passwordEncoder;

    @InjectMocks
    private JwtService jwtService;

    private User user;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(jwtService, "secretKey", "9E2zEACh8ywhVN0JNuOqN7irOwpMenVqpNBeGiCDyf8=");
        ReflectionTestUtils.setField(jwtService, "expiration", 1000L * 60 * 30); // 30 minutes
        ReflectionTestUtils.setField(jwtService, "refreshExpiration", 1000L * 60 * 60 * 24 * 60); // 60 days

        user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");
        authority.setUsername("testuser");
        user.setAuthorities(List.of(authority));
    }

    @Test
    void testGenerateAccessToken() {
        // Arrange

        // Act
        String token = jwtService.generateAccessToken(user);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());

        // Verify
        Claims claims = jwtService.extractAllClaims(token);
        assertEquals(user.getUsername(), claims.getSubject());
        assertEquals(user.getId(), Long.valueOf((int) claims.get("userId")));
        assertEquals(List.of("ROLE_USER"), claims.get("roles"));
    }

    @Test
    void testGenerateRefreshToken() {
        // Arrange
        Long refreshTokenId = 1L;

        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("user");

        ArrayList<Authority> authorities = new ArrayList<>();
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");
        authority.setUsername(mockUser.getUsername());
        authorities.add(authority);

        mockUser.setAuthorities(authorities);

        // Act
        String token = jwtService.generateRefreshToken(mockUser, refreshTokenId);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());

        // Verify
        Claims claims = jwtService.extractAllClaims(token);
        assertEquals(mockUser.getUsername(), claims.getSubject());
        assertEquals(refreshTokenId, Long.valueOf((int) claims.get("id")));
        assertEquals(mockUser.getId(), Long.valueOf((int) claims.get("userId")));
        assertNotNull(claims.get("deviceId"));
    }

    @Test
    void testValidateAccessToken_ValidToken_ReturnsTrue() {
        // Arrange
        String token = jwtService.generateAccessToken(user);

        // Act & Assert
        assertTrue(jwtService.validateAccessToken(token, user));
    }

    @Test
    void testValidateAccessToken_ExpiredToken_ReturnsFalse() {
        // Arrange
        ReflectionTestUtils.setField(jwtService, "expiration", -1000L); // expire token
        String expiredToken = jwtService.generateAccessToken(user);

        // Act & Assert
        assertFalse(jwtService.validateAccessToken(expiredToken, user));
    }

    @Test
    void testValidateAccessToken_TamperedToken_ReturnsFalse() {
        // Arrange
        String token = jwtService.generateAccessToken(user);
        String tampered = token.substring(0, token.length() - 2) + "aa"; // tamper with token

        // Act & Assert
        assertFalse(jwtService.validateAccessToken(tampered, user));
    }

    @Test
    void testValidateRefreshToken_ValidToken_ReturnsTrue() {
        // Arrange
        String refreshToken = jwtService.generateRefreshToken(user, 1L);

        RefreshToken storedToken = new RefreshToken();
        storedToken.setId(1L);
        storedToken.setUserId(1L);
        storedToken.setDeviceId(jwtService.extractAllClaims(refreshToken).get("deviceId").toString());
        storedToken.setToken(refreshToken);

        when(refreshTokenRepository.findById(1L)).thenReturn(Optional.of(storedToken));
        when(passwordEncoder.matches(storedToken.getToken(), refreshToken)).thenReturn(true);

        // Act & Assert
        assertTrue(jwtService.validateRefreshToken(refreshToken, user));

        // Verify
        verify(refreshTokenRepository).findById(1L);
        verify(passwordEncoder).matches(storedToken.getToken(), refreshToken);
    }

    @Test
    void testValidateRefreshToken_ExpiredToken_ReturnsFalse() {
        // Arrange
        ReflectionTestUtils.setField(jwtService, "refreshExpiration", -1000L); // expire token
        String refreshToken = jwtService.generateRefreshToken(user, 1L);

        // Act & Assert
        assertThrows(ExpiredJwtException.class, () -> jwtService.validateRefreshToken(refreshToken, user));
    }

    @Test
    void testValidateRefreshToken_TamperedToken_ReturnsFalse() {
        // Arrange
        String refreshToken = jwtService.generateRefreshToken(user, 1L);
        String tampered = refreshToken.substring(0, refreshToken.length() - 2) + "aa"; // tamper with token

        // Act & Assert
        assertThrows(SignatureException.class, () -> jwtService.validateRefreshToken(tampered, user));
    }

    @Test
    void testValidateExpiredRefreshToken_ReturnsTrue() {
        // Arrange
        ReflectionTestUtils.setField(jwtService, "refreshExpiration", -1000L); // expire token
        String refreshToken = jwtService.generateRefreshToken(user, 1L);

        Claims claims;
        try {
            claims = jwtService.extractAllClaims(refreshToken);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        }

        RefreshToken storedToken = new RefreshToken();
        storedToken.setId(1L);
        storedToken.setUserId(user.getId());
        storedToken.setDeviceId((String) claims.get("deviceId"));
        storedToken.setToken(refreshToken);

        when(refreshTokenRepository.findById(1L)).thenReturn(Optional.of(storedToken));
        when(passwordEncoder.matches(refreshToken, storedToken.getToken())).thenReturn(true);

        // Act
        boolean result = jwtService.validateExpiredRefreshToken(refreshToken, claims, user);

        // Assert
        assertTrue(result);

        verify(refreshTokenRepository).findById(1L);
        verify(passwordEncoder).matches(refreshToken, storedToken.getToken());
    }

    @Test
    void testInvalidateRefreshToken_DeletesSuccessfully() {
        RefreshToken token = new RefreshToken();
        token.setId(1L);
        when(refreshTokenRepository.findById(1L)).thenReturn(Optional.of(token));

        jwtService.invalidateRefreshToken(1L);

        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void testInvalidateRefreshToken_NotFound_Throws() {
        when(refreshTokenRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> jwtService.invalidateRefreshToken(1L));
    }
}
