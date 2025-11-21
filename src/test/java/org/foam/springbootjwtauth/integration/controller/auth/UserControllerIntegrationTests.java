package org.foam.springbootjwtauth.integration.controller.auth;

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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
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

    @Order(1)
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
            userService.deleteUser("user");
        }
    }

    @BeforeEach
    public void setupForGetUpdateDelete(TestInfo testInfo) {
        String testName = testInfo.getDisplayName();

        if (testName.contains("canDelete")
                || testName.contains("canUpdate")
                || testName.contains("canGet")) {

            userService.registerUser(new RegisterUserRequest(
                    "user",
                    "user@user.com",
                    "password")
            );
        }
    }

    @AfterEach
    public void cleanupForGetUpdate(TestInfo testInfo) {
        String testName = testInfo.getDisplayName();

        if (testName.contains("canUpdate") || testName.contains("canGet")) {

            userService.deleteUser("user");
        }
    }

    @Order(2)
    @Test
    public void canGetAsUser() throws Exception {
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
            refreshTokenRepository.deleteById(jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class));
        }
    }

    @Order(3)
    @Test
    public void canUpdateAsUser() throws Exception {
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
            refreshTokenRepository.deleteById(jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class));
        }
    }

    @Order(4)
    @Test
    public void canDeleteAsUser() {
        // login as user
        LoginResponse loginResponse = authService.login(new LoginRequest("user", "password"));

        // delete
        try {
            mockMvc.perform(delete("/user?username=user")
                            .header("Authorization", "Bearer " + loginResponse.getAccessToken()))
                    .andExpect(status().isNoContent());
        } catch (Exception e) {
            userService.deleteUser("user");
        } finally {
            // clean up
            refreshTokenRepository.deleteById(jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class));
        }

    }
}
