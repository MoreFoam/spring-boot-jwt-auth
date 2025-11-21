package org.foam.springbootjwtauth.integration.controller.auth;

import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        User user = userService.registerUser(new RegisterUserRequest("user", "user@user.com", "password"));
    }

    @AfterEach
    public void tearDown() {
        userService.deleteUser("user");
    }

    @Test
    @Order(1)
    public void canLogin() throws Exception {
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        MvcResult mvcResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.deviceId").exists())
                .andReturn();

        // clean up
        String responseBody = mvcResult.getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(responseBody, LoginResponse.class);

        refreshTokenRepository.deleteById(jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class));
    }

    @Test
    @Order(2)
    public void canLogout() throws Exception {
        // log in
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        JsonNode jsonResponse = objectMapper.readTree(responseBody);

        String accessToken = jsonResponse.get("accessToken").asString();
        String refreshToken = jsonResponse.get("refreshToken").asString();
        String deviceId = jsonResponse.get("deviceId").asString();

        // log out
        String logoutRequestJson = String.format("""
                    {
                        "refreshToken": "%s",
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, refreshToken, deviceId);

        try {
            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(logoutRequestJson))
                    .andExpect(status().isOk());
        } catch (Exception e) {
            // clean up
            // if the logout request fails, the refresh token will still be in the database, so delete it
            refreshTokenRepository.deleteById(jwtService.extractAllClaims(refreshToken).get("id", Long.class));
        }
    }

    @Test
    @Order(3)
    public void canRefresh() throws Exception {
        // log in
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        JsonNode jsonResponse = objectMapper.readTree(responseBody);

        String accessToken = jsonResponse.get("accessToken").asString();
        String refreshToken = jsonResponse.get("refreshToken").asString();
        String deviceId = jsonResponse.get("deviceId").asString();

        // refresh
        String refreshRequestJson = String.format("""
                    {
                        "refreshToken": "%s",
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, refreshToken, deviceId);

        try {
            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists());
        } finally {
            refreshTokenRepository.deleteById(jwtService.extractAllClaims(refreshToken).get("id", Long.class));
        }

    }
}
