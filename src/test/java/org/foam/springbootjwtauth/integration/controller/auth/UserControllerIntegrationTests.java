package org.foam.springbootjwtauth.integration.controller.auth;

import org.foam.springbootjwtauth.TestcontainersConfiguration;
import org.foam.springbootjwtauth.model.database.auth.Authority;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
        deleteUserIfExists("new-user");
        deleteUserIfExists("admin");
        deleteUserIfExists("other-user");
    }

    @AfterEach
    public void cleanupAfterEach() {
        deleteUserIfExists("user");
        deleteUserIfExists("new-user");
        deleteUserIfExists("admin");
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
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void cannotGetUserWithInvalidToken() throws Exception {
        mockMvc.perform(get("/user?userId=1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void corsPreflightAllowsPatchUserEndpoints() throws Exception {
        MvcResult result = mockMvc.perform(options("/user/username")
                        .header(HttpHeaders.ORIGIN, "http://localhost:3000")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
                .andExpect(status().isOk())
                .andReturn();

        Assertions.assertEquals(
                "http://localhost:3000",
                result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        Assertions.assertTrue(
                result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).contains("PATCH"));
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
    public void canGetAnotherUserAsAdmin() throws Exception {
        registerUser();
        registerAdmin();

        LoginResponse loginResponse = authService.login(new LoginRequest("admin", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();

            mockMvc.perform(get("/user?userId=" + userId)
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(userId))
                    .andExpect(jsonPath("$.username").value("user"));
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
    public void cannotUpdateUsernameThroughGenericUpdate() throws Exception {
        registerUser();

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            String updateUserJson = String.format("""
                        {
                            "id":"%s",
                            "username": "new-user",
                            "email": "user@user.com"
                        }
                    """, userId);

            mockMvc.perform(put("/user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUserJson))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string("Username cannot be changed through this endpoint. Use PATCH /user/username."));
        } finally {
            deleteRefreshToken(loginResponse);
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
    public void canUpdateUsernameAsUser() throws Exception {
        registerUser();

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            String updateUsernameJson = String.format("""
                        {
                            "id":"%s",
                            "username": "new-user",
                            "currentPassword": "password"
                        }
                    """, userId);

            mockMvc.perform(patch("/user/username")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUsernameJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(userId))
                    .andExpect(jsonPath("$.username").value("new-user"))
                    .andExpect(jsonPath("$.email").value("user@user.com"));

            Assertions.assertNull(userRepository.getUserByUsername("user"));
            Assertions.assertNotNull(userRepository.getUserByUsername("new-user"));
            Assertions.assertTrue(refreshTokenRepository.findById(refreshTokenId).isEmpty());

            mockMvc.perform(get("/user?userId=" + userId)
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isUnauthorized());

            LoginResponse newLoginResponse = authService.login(new LoginRequest("new-user", "password"));
            deleteRefreshToken(newLoginResponse);
        } finally {
            deleteRefreshToken(loginResponse);
            deleteUserIfExists("new-user");
        }
    }

    @Test
    public void cannotUpdateUsernameWithInvalidPassword() throws Exception {
        registerUser();

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            String updateUsernameJson = String.format("""
                        {
                            "id":"%s",
                            "username": "new-user",
                            "currentPassword": "bad-password"
                        }
                    """, userId);

            mockMvc.perform(patch("/user/username")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUsernameJson))
                    .andExpect(status().isBadRequest());
        } finally {
            deleteRefreshToken(loginResponse);
        }
    }

    @Test
    public void cannotUpdateAnotherUsersUsernameAsUser() throws Exception {
        registerUser();
        registerUser("other-user", "other@user.com");

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long otherUserId = userRepository.getUserByUsername("other-user").getId();
            String updateUsernameJson = String.format("""
                        {
                            "id":"%s",
                            "username": "new-user",
                            "currentPassword": "password"
                        }
                    """, otherUserId);

            mockMvc.perform(patch("/user/username")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUsernameJson))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(loginResponse);
        }
    }

    @Test
    public void canUpdatePasswordAsUser() throws Exception {
        registerUser();

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            String updatePasswordJson = String.format("""
                        {
                            "id":"%s",
                            "currentPassword": "password",
                            "newPassword": "new-password"
                        }
                    """, userId);

            mockMvc.perform(patch("/user/password")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updatePasswordJson))
                    .andExpect(status().isNoContent());

            Assertions.assertTrue(refreshTokenRepository.findById(refreshTokenId).isEmpty());

            LoginResponse newLoginResponse = authService.login(new LoginRequest("user", "new-password"));
            deleteRefreshToken(newLoginResponse);
        } finally {
            deleteRefreshToken(loginResponse);
        }
    }

    @Test
    public void cannotUpdatePasswordWithInvalidPassword() throws Exception {
        registerUser();

        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            String updatePasswordJson = String.format("""
                        {
                            "id":"%s",
                            "currentPassword": "bad-password",
                            "newPassword": "new-password"
                        }
                    """, userId);

            mockMvc.perform(patch("/user/password")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updatePasswordJson))
                    .andExpect(status().isBadRequest());
        } finally {
            deleteRefreshToken(loginResponse);
        }
    }

    @Test
    public void canUpdateAnotherUserAsAdmin() throws Exception {
        registerUser();
        registerAdmin();

        LoginResponse loginResponse = authService.login(new LoginRequest("admin", "password"));

        try {
            Long userId = userRepository.getUserByUsername("user").getId();
            String updateUserJson = String.format("""
                        {
                            "id":"%s",
                            "username": "user",
                            "email": "admin-updated@user.com"
                        }
                    """, userId);

            mockMvc.perform(put("/user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(updateUserJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(userId))
                    .andExpect(jsonPath("$.email").value("admin-updated@user.com"));
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

            Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
            Assertions.assertTrue(refreshTokenRepository.findById(refreshTokenId).isEmpty());
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

    private void registerAdmin() {
        registerUser("admin", "admin@user.com");

        User admin = userRepository.getUserByUsername("admin");
        Authority adminAuthority = new Authority();
        adminAuthority.setAuthority("ROLE_ADMIN");
        adminAuthority.setUser(admin);
        admin.getAuthorities().add(adminAuthority);
        userRepository.save(admin);
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
