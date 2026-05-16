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
        deleteUserIfExists("other-user");
    }

    @AfterEach
    public void cleanupAfterEach() {
        deleteUserIfExists("user");
        deleteUserIfExists("other-user");
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
    public void cannotRegisterDuplicateUsername() throws Exception {
        registerUser();

        String registerRequestJson = """
                    {
                        "username": "user",
                        "email": "other@user.com",
                        "password": "password"
                    }
                """;

        mockMvc.perform(post("/user/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequestJson))
                .andExpect(status().isConflict());
    }

    @Test
    public void cannotRegisterBlankUsername() throws Exception {
        String registerRequestJson = """
                    {
                        "username": "",
                        "email": "user@user.com",
                        "password": "password"
                    }
                """;

        mockMvc.perform(post("/user/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequestJson))
                .andExpect(status().isBadRequest());
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
    public void cannotGetUserWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/user?userId=1"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void cannotGetAnotherUserAsUser() throws Exception {
        registerUser();
        registerUser("other-user", "other@user.com");

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long otherUserId = userRepository.getUserByUsername("other-user").getId();

            mockMvc.perform(get("/user?userId=" + otherUserId)
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(loginResponse);
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
    public void cannotUpdateAnotherUserAsUser() throws Exception {
        registerUser();
        registerUser("other-user", "other@user.com");

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long otherUserId = userRepository.getUserByUsername("other-user").getId();
            String updateUserJson = String.format("""
                        {
                            "id":"%s",
                            "username": "other-user",
                            "email": "updated-other@user.com"
                        }
                    """, otherUserId);

            mockMvc.perform(put("/user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUserJson))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(loginResponse);
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

    @Test
    public void cannotDeleteAnotherUserAsUser() throws Exception {
        registerUser();
        registerUser("other-user", "other@user.com");

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            mockMvc.perform(delete("/user?username=other-user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(loginResponse);
        }
    }

    private void registerUser() {
        registerUser("user", "user@user.com");
    }

    private void registerUser(String username, String email) {
        userService.registerUser(new RegisterUserRequest(
                username,
                email,
                "password")
        );
    }

    private void deleteRefreshToken(LoginResponse loginResponse) {
        Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
        refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
    }

    private void deleteUserIfExists(String username) {
        User user = userRepository.getUserByUsername(username);
        if (user != null) {
            userService.deleteUser(username);
        }
    }
}
