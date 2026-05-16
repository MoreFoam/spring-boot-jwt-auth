package org.foam.springbootjwtauth.integration.controller.auth;

import jakarta.servlet.http.Cookie;
import org.foam.springbootjwtauth.TestcontainersConfiguration;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
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
        userService.registerUser(new RegisterUserRequest("user", "user@user.com", "password"));
    }

    @AfterEach
    public void tearDown() {
        userService.deleteUser("user");
    }

    @Test
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

        Long refreshTokenId = jwtService.extractAllClaims(loginResponse.getRefreshToken()).get("id", Long.class);
        refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
    }

    @Test
    public void cannotLoginWithInvalidPassword() throws Exception {
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "bad-password"
                    }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void cannotLoginWithBlankUsername() throws Exception {
        String loginRequestJson = """
                    {
                        "username": "",
                        "password": "password"
                    }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isBadRequest());
    }

    @Test
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

        Long refreshTokenId = jwtService.extractAllClaims(refreshToken).get("id", Long.class);

        try {
            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(logoutRequestJson))
                    .andExpect(status().isOk());
        } finally {
            refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
        }
    }

    @Test
    public void cannotRefreshWithInvalidRefreshToken() throws Exception {
        String refreshRequestJson = """
                    {
                        "refreshToken": "invalid-refresh-token",
                        "username": "user",
                        "deviceId":"device-id"
                    }
                """;

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequestJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void cannotLogoutWithInvalidRefreshToken() throws Exception {
        String logoutRequestJson = """
                    {
                        "refreshToken": "invalid-refresh-token",
                        "username": "user",
                        "deviceId":"device-id"
                    }
                """;

        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutRequestJson))
                .andExpect(status().isBadRequest());
    }

    @Test
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
            Long refreshTokenId = jwtService.extractAllClaims(refreshToken).get("id", Long.class);
            refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
        }

    }

    @Test
    public void canWebLoginWithRefreshTokenCookie() throws Exception {
        WebLoginResult webLoginResult = webLogin();

        try {
            assertNotNull(webLoginResult.refreshToken());
            assertTrue(webLoginResult.setCookieHeader().contains("HttpOnly"));
            assertTrue(webLoginResult.setCookieHeader().contains("SameSite=Lax"));
            assertTrue(webLoginResult.setCookieHeader().contains("Path=/api/auth/web"));
            assertTrue(webLoginResult.setCookieHeader().contains("Max-Age=5184000"));
        } finally {
            deleteRefreshToken(webLoginResult.refreshToken());
        }
    }

    @Test
    public void canWebRefreshWithRefreshTokenCookie() throws Exception {
        WebLoginResult webLoginResult = webLogin();

        String refreshRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        try {
            mockMvc.perform(post("/auth/web/refresh")
                            .cookie(webLoginResult.refreshTokenCookie())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists());
        } finally {
            deleteRefreshToken(webLoginResult.refreshToken());
        }
    }

    @Test
    public void cannotWebRefreshWithoutRefreshTokenCookie() throws Exception {
        String refreshRequestJson = """
                    {
                        "username": "user",
                        "deviceId":"device-id"
                    }
                """;

        mockMvc.perform(post("/auth/web/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequestJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void canWebLogoutWithRefreshTokenCookie() throws Exception {
        WebLoginResult webLoginResult = webLogin();
        Long refreshTokenId = jwtService.extractAllClaims(webLoginResult.refreshToken()).get("id", Long.class);

        String logoutRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        MvcResult logoutResult = mockMvc.perform(post("/auth/web/logout")
                        .cookie(webLoginResult.refreshTokenCookie())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutRequestJson))
                .andExpect(status().isOk())
                .andReturn();

        String clearCookieHeader = logoutResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(clearCookieHeader);
        assertTrue(clearCookieHeader.contains("refreshToken="));
        assertTrue(clearCookieHeader.contains("Max-Age=0"));
        assertTrue(refreshTokenRepository.findById(refreshTokenId).isEmpty());
    }

    @Test
    public void canWebLogoutWithoutRefreshTokenCookie() throws Exception {
        String logoutRequestJson = """
                    {
                        "username": "user",
                        "deviceId":"device-id"
                    }
                """;

        MvcResult logoutResult = mockMvc.perform(post("/auth/web/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutRequestJson))
                .andExpect(status().isOk())
                .andReturn();

        String clearCookieHeader = logoutResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(clearCookieHeader);
        assertTrue(clearCookieHeader.contains("refreshToken="));
        assertTrue(clearCookieHeader.contains("Max-Age=0"));
    }

    private WebLoginResult webLogin() throws Exception {
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        MvcResult loginResult = mockMvc.perform(post("/auth/web/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.deviceId").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andReturn();

        String setCookieHeader = loginResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookieHeader);

        JsonNode loginJsonResponse = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String accessToken = loginJsonResponse.get("accessToken").asString();
        String deviceId = loginJsonResponse.get("deviceId").asString();
        String refreshToken = extractCookieValue(setCookieHeader, "refreshToken");
        assertFalse(refreshToken.isBlank());

        return new WebLoginResult(
                accessToken,
                refreshToken,
                deviceId,
                new Cookie("refreshToken", refreshToken),
                setCookieHeader);
    }

    private String extractCookieValue(String setCookieHeader, String cookieName) {
        String cookiePrefix = cookieName + "=";
        String cookieNameAndValue = setCookieHeader.split(";", 2)[0];

        if (!cookieNameAndValue.startsWith(cookiePrefix)) {
            throw new IllegalArgumentException("Set-Cookie header did not contain " + cookieName);
        }

        return cookieNameAndValue.substring(cookiePrefix.length());
    }

    private void deleteRefreshToken(String refreshToken) {
        Long refreshTokenId = jwtService.extractAllClaims(refreshToken).get("id", Long.class);
        refreshTokenRepository.findById(refreshTokenId).ifPresent(refreshTokenRepository::delete);
    }

    private record WebLoginResult(
            String accessToken,
            String refreshToken,
            String deviceId,
            Cookie refreshTokenCookie,
            String setCookieHeader) {
    }
}
