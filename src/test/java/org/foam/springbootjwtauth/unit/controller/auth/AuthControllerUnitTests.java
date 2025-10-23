package org.foam.springbootjwtauth.unit.controller.auth;

import org.foam.springbootjwtauth.controller.auth.AuthController;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.LogoutRequest;
import org.foam.springbootjwtauth.model.request.auth.RefreshRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.model.response.auth.RefreshResponse;
import org.foam.springbootjwtauth.service.auth.AuthService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthControllerUnitTests {

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    @Test
    void testLoginReturnsTokensAndDeviceId() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("user", "password");
        LoginResponse mockResponse = new LoginResponse("access-token", "refresh-token", "device-id");
        when(authService.login(loginRequest)).thenReturn(mockResponse);

        // Act
        ResponseEntity<LoginResponse> response = authController.login(loginRequest);

        // Assert
        Assertions.assertNotNull(response.getBody());
        assertEquals("access-token", response.getBody().getAccessToken());
        assertEquals("refresh-token", response.getBody().getRefreshToken());
        assertEquals("device-id", response.getBody().getDeviceId());

        // Verify controller called the service
        verify(authService, times(1)).login(loginRequest);
    }

    @Test
    void testLoginAuthenticationException() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("user", "bad-password");
        when(authService.login(loginRequest)).thenThrow(new BadCredentialsException("Bad credentials"));

        // Act
        ResponseEntity<?> response = authController.login(loginRequest);

        // Assert
        assertEquals(401, response.getStatusCode().value());
        assertNull(response.getBody());

        // Verify controller called the service
        verify(authService, times(1)).login(loginRequest);
    }

    @Test
    void testLogout() {
        // Arrange
        LogoutRequest logoutRequest = new LogoutRequest("user", "refresh-token", "device-id");

        // Act
        ResponseEntity<Void> response = authController.logout(logoutRequest);

        // Assert
        assertEquals(200, response.getStatusCode().value());
        assertNull(response.getBody());

        // Verify
        verify(authService, times(1)).logout(logoutRequest);
    }

    @Test
    void testRefresh() {
        // Arrange
        RefreshRequest refreshRequest = new RefreshRequest("refresh-token", "username", "device-id");
        RefreshResponse refreshResponse = new RefreshResponse("new-access-token");
        when(authService.refresh(refreshRequest)).thenReturn(refreshResponse);

        // Act
        ResponseEntity<RefreshResponse> response = authController.refresh(refreshRequest);

        // Assert
        assertEquals(200, response.getStatusCode().value());
        Assertions.assertNotNull(response.getBody());
        assertEquals("new-access-token", response.getBody().getAccessToken());

        // Verify
        verify(authService, times(1)).refresh(refreshRequest);
    }
}
