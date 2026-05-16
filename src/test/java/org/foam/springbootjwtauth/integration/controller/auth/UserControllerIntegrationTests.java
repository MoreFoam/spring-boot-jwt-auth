package org.foam.springbootjwtauth.integration.controller.auth;

import org.foam.springbootjwtauth.TestcontainersConfiguration;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.repository.auth.UserRepository;
import org.foam.springbootjwtauth.service.auth.AuthService;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public class UserControllerIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthService authService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @BeforeEach
    public void cleanupBeforeEach() {
        deleteUserIfExists("user");
    }

    @AfterEach
    public void cleanupAfterEach() {
        deleteUserIfExists("user");
    }

    @Test
    public void canRegister() throws Exception {
        String registerRequestJson = """
                    {
                        "username": "user",
                        "email": "user@user.com",
                        "password": "password"
                    }
                """;

        try {
            mockMvc.perform(post("/user/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(registerRequestJson))
                    .andExpect(status().is(201));
        } finally {
            deleteUserIfExists("user");
        }
    }

    @Test
    public void canGetAsUser() throws Exception {
        registerUser();
        // login as user
        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {

            Long userId = jwtService.extractAllClaims(loginResponse.getAccessToken()).get("userId", Long.class);

            // get user
            mockMvc.perform(get("/user?userId=" + userId)
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(userId))
                    .andExpect(jsonPath("$.username").value("user"))
                    .andExpect(jsonPath("$.email").value("user@user.com"));
        } finally {
            // clean up
            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
        }
    }

    @Test
    public void canUpdateAsUser() throws Exception {
        registerUser();
        // login as user
        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            // update user
            Long userId = userRepository.getUserByUsername("user").getId();
            String updateUserJson = String.format("""
                        {
                            "id":"%s",
                            "username": "user",
                            "email": "new-email@user.com"
                        }
                    """, userId);

            mockMvc.perform(put("/user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUserJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(userId))
                    .andExpect(jsonPath("$.username").value("user"))
                    .andExpect(jsonPath("$.email").value("new-email@user.com"));
        } finally {
            // clean up
            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
        }
    }

    @Test
    public void canDeleteAsUser() throws Exception {
        registerUser();
        // login as user
        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        // delete
        try {
            mockMvc.perform(delete("/user?username=user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isNoContent());
        } finally {
            // clean up
            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
            deleteUserIfExists("user");
        }

    }

    private void registerUser() {
        userService.registerUser(new RegisterUserRequest(
                "user",
                "user@user.com",
                "password")
        );
    }

    private void deleteUserIfExists(String username) {
        User user = userRepository.getUserByUsername(username);
        if (user != null) {
            userService.deleteUser(username);
        }
    }
}
