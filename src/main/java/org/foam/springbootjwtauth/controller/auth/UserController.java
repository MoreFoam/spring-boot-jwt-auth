package org.foam.springbootjwtauth.controller.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.foam.springbootjwtauth.annotation.LogMethod;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.request.auth.UpdateUserRequest;
import org.foam.springbootjwtauth.model.response.auth.UserResponse;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
@Validated
public class UserController {

    private final UserService userService;

    private final ModelMapper modelMapper;

    @Autowired
    public UserController(UserService userService, ModelMapper modelMapper) {
        this.userService = userService;
        this.modelMapper = modelMapper;
    }

    @LogMethod
    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
        userService.registerUser(registerUserRequest);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @LogMethod
    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN') or #userId == principal.id")
    public ResponseEntity<UserResponse> getUser(@NotNull @RequestParam Long userId) {
        User user = userService.getUser(userId);

        UserResponse userResponse = modelMapper.map(user, UserResponse.class);

        return ResponseEntity.ok().body(userResponse);
    }

    @LogMethod
    @PutMapping
    @PreAuthorize("hasRole('ROLE_ADMIN') or #updateUserRequest.username() == authentication.name")
    public ResponseEntity<UserResponse> updateUser(@Valid @RequestBody UpdateUserRequest updateUserRequest) {
        User user = userService.updateUser(updateUserRequest);

        UserResponse userResponse = modelMapper.map(user, UserResponse.class);

        return ResponseEntity.ok().body(userResponse);
    }

    @LogMethod
    @DeleteMapping
    @PreAuthorize("hasRole('ROLE_ADMIN') or #username == authentication.name")
    public ResponseEntity<Void> deleteUser(@NotNull @RequestParam String username) {
        userService.deleteUser(username);

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
