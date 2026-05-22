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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring-boot-jwt-auth.security.jwt.secret-key=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdW5pdC10ZXN0cw=="
})
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

        String newRefreshToken = null;

        try {
            MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.refreshToken").exists())
                    .andReturn();

            JsonNode refreshJsonResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
            newRefreshToken = refreshJsonResponse.get("refreshToken").asString();
            Long oldRefreshTokenId = jwtService.extractAllClaims(refreshToken).get("id", Long.class);
            assertTrue(refreshTokenRepository.findById(oldRefreshTokenId).isEmpty());
        } finally {
            deleteRefreshTokenIfPresent(refreshToken);
            deleteRefreshTokenIfPresent(newRefreshToken);
        }

    }

    @Test
    public void cannotReuseRotatedRefreshToken() throws Exception {
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
                .andReturn();

        JsonNode jsonResponse = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String refreshToken = jsonResponse.get("refreshToken").asString();
        String deviceId = jsonResponse.get("deviceId").asString();
        String refreshRequestJson = String.format("""
                    {
                        "refreshToken": "%s",
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, refreshToken, deviceId);

        String newRefreshToken = null;

        try {
            MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isOk())
                    .andReturn();

            JsonNode refreshJsonResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
            newRefreshToken = refreshJsonResponse.get("refreshToken").asString();

            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string("Invalid refresh token."));
        } finally {
            deleteRefreshTokenIfPresent(refreshToken);
            deleteRefreshTokenIfPresent(newRefreshToken);
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
    public void cannotWebLoginWithoutCsrfToken() throws Exception {
        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        mockMvc.perform(post("/auth/web/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequestJson))
                .andExpect(status().isForbidden());
    }

    @Test
    public void canWebRefreshWithRefreshTokenCookieAndCsrfToken() throws Exception {
        WebLoginResult webLoginResult = webLogin();

        String refreshRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        String newRefreshToken = null;

        try {
            CsrfResult csrf = getCsrfToken();

            MvcResult refreshResult = mockMvc.perform(post("/auth/web/refresh")
                            .cookie(csrf.cookie())
                            .header("X-XSRF-TOKEN", csrf.token())
                            .cookie(webLoginResult.refreshTokenCookie())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").exists())
                    .andExpect(jsonPath("$.refreshToken").doesNotExist())
                    .andReturn();

            String setCookieHeader = refreshResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
            assertNotNull(setCookieHeader);
            assertTrue(setCookieHeader.contains("HttpOnly"));
            newRefreshToken = extractCookieValue(setCookieHeader, "refreshToken");
            assertFalse(newRefreshToken.isBlank());

            Long oldRefreshTokenId = jwtService.extractAllClaims(webLoginResult.refreshToken()).get("id", Long.class);
            assertTrue(refreshTokenRepository.findById(oldRefreshTokenId).isEmpty());
        } finally {
            deleteRefreshTokenIfPresent(webLoginResult.refreshToken());
            deleteRefreshTokenIfPresent(newRefreshToken);
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

        CsrfResult csrf = getCsrfToken();

        mockMvc.perform(post("/auth/web/refresh")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequestJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void canWebLogoutWithRefreshTokenCookieAndCsrfToken() throws Exception {
        WebLoginResult webLoginResult = webLogin();
        Long refreshTokenId = jwtService.extractAllClaims(webLoginResult.refreshToken()).get("id", Long.class);

        String logoutRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        CsrfResult csrf = getCsrfToken();

        MvcResult logoutResult = mockMvc.perform(post("/auth/web/logout")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
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

        CsrfResult csrf = getCsrfToken();

        MvcResult logoutResult = mockMvc.perform(post("/auth/web/logout")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutRequestJson))
                .andExpect(status().isOk())
                .andReturn();

        String clearCookieHeader = logoutResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(clearCookieHeader);
        assertTrue(clearCookieHeader.contains("refreshToken="));
        assertTrue(clearCookieHeader.contains("Max-Age=0"));
    }

    @Test
    public void cannotWebLogoutWithoutCsrfToken() throws Exception {
        WebLoginResult webLoginResult = webLogin();

        String logoutRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        try {
            mockMvc.perform(post("/auth/web/logout")
                            .cookie(webLoginResult.refreshTokenCookie())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(logoutRequestJson))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(webLoginResult.refreshToken());
        }
    }

    @Test
    public void canGetCsrfCookie() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/auth/web/csrf")
                        .session(new MockHttpSession())) // Force new session, as the mock session from other tests may already have created a CSRF token
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
                .andReturn();

        String setCookieHeader = csrfResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);

        assertNotNull(setCookieHeader);
        assertTrue(setCookieHeader.contains("XSRF-TOKEN="));

        Cookie csrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(csrfCookie);
        assertEquals("/", csrfCookie.getPath());
        assertEquals("Lax", csrfCookie.getAttribute("SameSite"));
        assertFalse(csrfCookie.isHttpOnly());

        String csrfToken = extractCookieValue(setCookieHeader, "XSRF-TOKEN");
        JsonNode csrfJsonResponse = objectMapper.readTree(csrfResult.getResponse().getContentAsString());

        assertFalse(csrfToken.isBlank());
        assertEquals(csrfToken, csrfJsonResponse.get("token").asString());
    }

    @Test
    public void cannotWebRefreshWithoutCsrfToken() throws Exception {
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
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(webLoginResult.refreshToken());
        }
    }

    @Test
    public void cannotWebRefreshWithCsrfCookieOnly() throws Exception {
        WebLoginResult webLoginResult = webLogin();

        String refreshRequestJson = String.format("""
                    {
                        "username": "user",
                        "deviceId":"%s"
                    }
                """, webLoginResult.deviceId());

        try {
            CsrfResult csrf = getCsrfToken();

            mockMvc.perform(post("/auth/web/refresh")
                            .cookie(csrf.cookie())
                            .cookie(webLoginResult.refreshTokenCookie())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(refreshRequestJson))
                    .andExpect(status().isForbidden());
        } finally {
            deleteRefreshToken(webLoginResult.refreshToken());
        }
    }

    private CsrfResult getCsrfToken() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/auth/web/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
                .andReturn();

        String setCookieHeader = csrfResult.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookieHeader);

        JsonNode csrfJsonResponse = objectMapper.readTree(csrfResult.getResponse().getContentAsString());
        String token = csrfJsonResponse.get("token").asString();
        assertFalse(token.isBlank());
        assertEquals(extractCookieValue(setCookieHeader, "XSRF-TOKEN"), token);

        return new CsrfResult(token, new Cookie("XSRF-TOKEN", token));
    }

    private record CsrfResult(String token, Cookie cookie) {
    }

    private WebLoginResult webLogin() throws Exception {
        CsrfResult csrf = getCsrfToken();

        String loginRequestJson = """
                    {
                        "username": "user",
                        "password": "password"
                    }
                """;

        MvcResult loginResult = mockMvc.perform(post("/auth/web/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
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

    private void deleteRefreshTokenIfPresent(String refreshToken) {
        if (refreshToken != null) {
            deleteRefreshToken(refreshToken);
        }
    }

    private record WebLoginResult(
            String accessToken,
            String refreshToken,
            String deviceId,
            Cookie refreshTokenCookie,
            String setCookieHeader) {
    }
}
