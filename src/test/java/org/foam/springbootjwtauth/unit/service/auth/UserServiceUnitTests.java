package org.foam.springbootjwtauth.unit.service.auth;

import org.foam.springbootjwtauth.exception.auth.UserAlreadyExistsException;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.request.auth.UpdateUserRequest;
import org.foam.springbootjwtauth.repository.auth.UserRepository;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceUnitTests {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    UserService userService;

    @Test
    void testRegister() {
        // Arrange
        RegisterUserRequest registerUserRequest = new RegisterUserRequest("username", "email", "password");

        User user = new User();
        user.setId(1L);
        user.setUsername(registerUserRequest.username());
        user.setEmail(registerUserRequest.email());

        when(userRepository.getUserByEmail(registerUserRequest.email())).thenReturn(null);
        when(userRepository.getUserByUsername(registerUserRequest.username())).thenReturn(null);
        when(passwordEncoder.encode(registerUserRequest.password())).thenReturn("encoded-password");
        when(userRepository.save(any())).thenReturn(user);

        // Act
        User result = userService.registerUser(registerUserRequest);

        // Assert
        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("username", result.getUsername());
        assertEquals("email", result.getEmail());

        // Verify
        verify(userRepository, times(1)).getUserByEmail(registerUserRequest.email());
        verify(userRepository, times(1)).getUserByUsername(registerUserRequest.username());
        verify(passwordEncoder, times(1)).encode(registerUserRequest.password());
        verify(userRepository, times(1)).save(any());
    }

    @Test
    void testRegister_EmailAlreadyExists() {
        // Arrange
        RegisterUserRequest registerUserRequest = new RegisterUserRequest("username", "email", "password");

        User user = new User();
        user.setId(1L);
        user.setUsername(registerUserRequest.username());
        user.setEmail(registerUserRequest.email());

        when(userRepository.getUserByEmail(registerUserRequest.email())).thenReturn(user);

        // Act
        assertThrows(UserAlreadyExistsException.class, () -> userService.registerUser(registerUserRequest));

        // Verify
        verify(userRepository, times(1)).getUserByEmail(registerUserRequest.email());
        verify(userRepository, never()).getUserByUsername(registerUserRequest.username());
        verify(passwordEncoder, never()).encode(registerUserRequest.password());
        verify(userRepository, never()).save(any());
    }

    @Test
    void testRegister_UsernameAlreadyExists() {
        // Arrange
        RegisterUserRequest registerUserRequest = new RegisterUserRequest("username", "email", "password");

        User user = new User();
        user.setId(1L);
        user.setUsername(registerUserRequest.username());
        user.setEmail(registerUserRequest.email());

        when(userRepository.getUserByEmail(registerUserRequest.email())).thenReturn(null);
        when(userRepository.getUserByUsername(registerUserRequest.username())).thenReturn(user);

        // Act
        assertThrows(UserAlreadyExistsException.class, () -> userService.registerUser(registerUserRequest));

        // Verify
        verify(userRepository, times(1)).getUserByEmail(registerUserRequest.email());
        verify(userRepository, times(1)).getUserByUsername(registerUserRequest.username());
        verify(passwordEncoder, never()).encode(registerUserRequest.password());
        verify(userRepository, never()).save(any());
    }

    @Test
    void testLoadUserByUsername() {
        // Arrange
        String username = "username";

        User user = new User();
        user.setId(1L);
        user.setUsername(username);

        when(userRepository.getUserByUsername(username)).thenReturn(user);

        // Act
        User returnedUser = userService.loadUserByUsername(username);

        // Assert
        assertNotNull(returnedUser);
        assertEquals(1L, returnedUser.getId());
        assertEquals(username, returnedUser.getUsername());

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
    }

    @Test
    void testLoadUserByUsername_UserNotFound() {
        // Arrange
        String username = "bad-username";

        when(userRepository.getUserByUsername(username)).thenReturn(null);

        // Act
        assertThrows(UsernameNotFoundException.class, () -> userService.loadUserByUsername(username));

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
    }

    @Test
    void testUpdateUser() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest(1L, "username", "new-email");

        User user = new User();
        user.setId(1L);
        user.setUsername(updateUserRequest.username());
        user.setEmail(updateUserRequest.email());

        when(userRepository.findById(updateUserRequest.id())).thenReturn(java.util.Optional.of(user));
        when(userRepository.save(any())).thenReturn(user);

        // Act
        User updatedUser = userService.updateUser(updateUserRequest);

        // Assert
        assertNotNull(updatedUser);
        assertEquals(1L, updatedUser.getId());
        assertEquals("username", updatedUser.getUsername());
        assertEquals("new-email", updatedUser.getEmail());

        // Verify
        verify(userRepository, times(1)).findById(updateUserRequest.id());
        verify(userRepository, times(1)).save(any());
    }

    @Test
    void testUpdateUser_UserNotFound() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest(1L, "username", "new-email");

        when(userRepository.findById(updateUserRequest.id())).thenReturn(java.util.Optional.empty());

        // Act
        NoSuchElementException exception = assertThrows(NoSuchElementException.class, () -> userService.updateUser(updateUserRequest));

        // Verify
        verify(userRepository, times(1)).findById(updateUserRequest.id());
        verify(userRepository, never()).save(any());
    }

    @Test
    void testDeleteUser() {
        // Arrange
        String username = "username";

        User user = new User();
        user.setId(1L);
        user.setUsername(username);

        when(userRepository.getUserByUsername(username)).thenReturn(user);

        // Act
        userService.deleteUser(username);

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
        verify(userRepository, times(1)).delete(user);
    }

    @Test
    void testDeleteUser_UserNotFound() {
        // Arrange
        String username = "username";

        when(userRepository.getUserByUsername(username)).thenReturn(null);

        // Act
        assertThrows(UsernameNotFoundException.class, () -> userService.deleteUser(username));

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
        verify(userRepository, never()).delete(any());
    }

    @Test
    void testGetUserByUserId() {
        // Arrange
        Long userId = 1L;

        User user = new User();
        user.setId(userId);
        user.setUsername("user");
        user.setEmail("user@mail.com");

        when(userRepository.findById(userId)).thenReturn(java.util.Optional.of(user));

        // Act
        User returnedUser = userService.getUser(userId);

        // Assert
        assertNotNull(returnedUser);
        assertEquals(userId, returnedUser.getId());
        assertEquals("user", returnedUser.getUsername());
        assertEquals("user@mail.com", returnedUser.getEmail());

        // Verify
        verify(userRepository, times(1)).findById(userId);
    }

    @Test
    void testGetUserByUserId_UserNotFound() {
        // Arrange
        Long userId = 1L;

        when(userRepository.findById(userId)).thenReturn(java.util.Optional.empty());

        // Act
        assertThrows(NoSuchElementException.class, () -> userService.getUser(userId));

        // Verify
        verify(userRepository, times(1)).findById(userId);
    }

    @Test
    void testGetUserByEmail() {
        // Arrange
        String email = "mail@user.com";

        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setEmail(email);

        when(userRepository.getUserByEmail(email)).thenReturn(user);

        // Act
        User returnedUser = userService.getUser(email);

        // Assert
        assertNotNull(returnedUser);
        assertEquals(1L, returnedUser.getId());
        assertEquals("user", returnedUser.getUsername());
        assertEquals(email, returnedUser.getEmail());

        // Verify
        verify(userRepository, times(1)).getUserByEmail(email);
    }

    @Test
    void testGetUserByEmail_UserNotFound() {
        // Arrange
        String email = "mail@user.com";

        when(userRepository.getUserByEmail(email)).thenReturn(null);

        // Act
        assertThrows(NoSuchElementException.class, () -> userService.getUser(email));

        // Verify
        verify(userRepository, times(1)).getUserByEmail(email);
    }

    @Test
    void testFindUsersByUsernameLikeOrEmailLike() {
        // Arrange
        String usernamePart = "john";
        String emailPart = "example.com";
        int page = 0;
        int size = 10;

        User user1 = new User();
        user1.setUsername("john123");
        user1.setEmail("john@example.com");

        User user2 = new User();
        user2.setUsername("john456");
        user2.setEmail("john.doe@example.com");

        List<User> users = List.of(user1, user2);
        Page<User> userPage = new PageImpl<>(users);

        Pageable expectedPageable = PageRequest.of(page, size, Sort.by("username").ascending());

        when(userRepository.findByUsernameLikeOrEmailLike("%" + usernamePart + "%", "%" + emailPart + "%", expectedPageable))
                .thenReturn(userPage);

        // Act
        Page<User> result = userService.findUsersByUsernameLikeOrEmailLike(usernamePart, emailPart, page, size);

        // Assert
        assertNotNull(result);
        assertEquals(2, result.getContent().size());
        assertEquals("john123", result.getContent().get(0).getUsername());
        assertEquals("john456", result.getContent().get(1).getUsername());

        // Verify
        verify(userRepository, times(1))
                .findByUsernameLikeOrEmailLike("%" + usernamePart + "%", "%" + emailPart + "%", expectedPageable);
    }

    @Test
    void testDoesUsernameExist_True() {
        // Arrange
        String username = "username";

        User user = new User();
        user.setId(1L);
        user.setUsername(username);

        when(userRepository.getUserByUsername(username)).thenReturn(user);

        // Act
        Boolean result = userService.doesUsernameExist(username);

        // Assert
        assertNotNull(result);
        assertTrue(result);

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
    }

    @Test
    void testDoesUsernameExist_False() {
        // Arrange
        String username = "non-existent-username";

        when(userRepository.getUserByUsername(username)).thenReturn(null);

        // Act
        Boolean result = userService.doesUsernameExist(username);

        // Assert
        assertNotNull(result);
        assertFalse(result);

        // Verify
        verify(userRepository, times(1)).getUserByUsername(username);
    }

    @Test
    void testDoesEmailExist_True() {
        // Arrange
        String email = "user@mail.com";

        User user = new User();
        user.setId(1L);
        user.setUsername("user");
        user.setEmail(email);

        when(userRepository.getUserByEmail(email)).thenReturn(user);

        // Act
        Boolean result = userService.doesEmailExist(email);

        // Assert
        assertNotNull(result);
        assertTrue(result);

        // Verify
        verify(userRepository, times(1)).getUserByEmail(email);
    }

    @Test
    void testDoesEmailExist_False() {
        // Arrange
        String email = "user@mail.com";

        when(userRepository.getUserByEmail(email)).thenReturn(null);

        // Act
        Boolean result = userService.doesEmailExist(email);

        // Assert
        assertNotNull(result);
        assertFalse(result);

        // Verify
        verify(userRepository, times(1)).getUserByEmail(email);
    }

    @Test
    void testGetUsersInPage() {
        // Arrange
        int page = 0;
        int size = 10;

        User user1 = new User();
        user1.setUsername("john123");
        user1.setEmail("john@example.com");

        User user2 = new User();
        user2.setUsername("john456");
        user2.setEmail("john.doe@example.com");

        List<User> users = List.of(user1, user2);

        Pageable expectedPageable = PageRequest.of(page, size, Sort.by("username").ascending());
        Page<User> userPage = new PageImpl<>(users, expectedPageable, users.size());

        when(userRepository.findAll(expectedPageable)).thenReturn(userPage);

        // Act
        Page<User> result = userService.getUsersInPage(page, size);

        // Assert
        assertNotNull(result);
        assertEquals(2, result.getTotalElements());
        assertEquals(1, result.getTotalPages());
        assertEquals(2, result.getContent().size());
        assertEquals(Sort.by("username").ascending(), result.getPageable().getSort());

        // Verify
        verify(userRepository, times(1)).findAll(expectedPageable);
    }
}
