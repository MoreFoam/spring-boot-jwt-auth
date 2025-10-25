package org.foam.springbootjwtauth.unit.controller.auth;

import org.foam.springbootjwtauth.controller.auth.UserController;
import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.request.auth.UpdateUserRequest;
import org.foam.springbootjwtauth.model.response.auth.UserResponse;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserControllerUnitTests {

    @Mock
    UserService userService;

    @Mock
    ModelMapper modelMapper;

    @InjectMocks
    UserController userController;

    @Test
    void testRegisterUser() {
        // Arrange
        RegisterUserRequest registerUserRequest = new RegisterUserRequest("username", "user@mail.com", "password");

        // Act
        ResponseEntity<Void> response = userController.registerUser(registerUserRequest);

        // Assert
        assertEquals(201, response.getStatusCode().value());

        // Verify controller called the service
        verify(userService, times(1)).registerUser(registerUserRequest);
    }

    @Test
    void testGetUser() {
        // Arrange
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");

        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setPassword("password");
        user.setEmail("user@mail.com");
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        user.setAuthorities(List.of(authority));

        when(userService.getUser(anyLong())).thenReturn(user);

        when(modelMapper.map(any(User.class), eq(UserResponse.class)))
                .thenAnswer(invocation -> {
                    User u = invocation.getArgument(0);
                    return new UserResponse(u.getId(), u.getUsername(), u.getEmail());
                });

        // Act
        ResponseEntity<UserResponse> response = userController.getUser(1L);

        // Assert
        assertEquals(200, response.getStatusCode().value());
        Assertions.assertNotNull(response.getBody());
        assertEquals(1L, response.getBody().getId());
        assertEquals("user", response.getBody().getUsername());
        assertEquals("user@mail.com", response.getBody().getEmail());

        // Verify controller called the service
        verify(userService, times(1)).getUser(1L);
    }

    @Test
    void testUpdateUser() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest(1L, "user", "updated@mail.com");

        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");

        User updatedUser = new User();
        updatedUser.setId(1L);
        updatedUser.setUsername("user");
        updatedUser.setPassword("password");
        updatedUser.setEmail("updated@mail.com");
        updatedUser.setEnabled(true);
        updatedUser.setAccountNonExpired(true);
        updatedUser.setAccountNonLocked(true);
        updatedUser.setCredentialsNonExpired(true);
        updatedUser.setAuthorities(List.of(authority));

        when(userService.updateUser(updateUserRequest)).thenReturn(updatedUser);

        when(modelMapper.map(any(User.class), eq(UserResponse.class)))
                .thenAnswer(invocation -> {
                    User u = invocation.getArgument(0);
                    return new UserResponse(u.getId(), u.getUsername(), u.getEmail());
                });

        // Act
        ResponseEntity<UserResponse> response = userController.updateUser(updateUserRequest);

        // Assert
        assertEquals(200, response.getStatusCode().value());
        Assertions.assertNotNull(response.getBody());
        assertEquals(1L, response.getBody().getId());
        assertEquals("user", response.getBody().getUsername());
        assertEquals("updated@mail.com", response.getBody().getEmail());

        // Verify controller called the service
        verify(userService, times(1)).updateUser(updateUserRequest);
    }

    @Test
    void testDeleteUser() {

        // Act
        ResponseEntity<Void> response = userController.deleteUser("user");

        // Assert
        assertEquals(204, response.getStatusCode().value());

        // Verify controller called the service
        verify(userService, times(1)).deleteUser("user");
    }
}
