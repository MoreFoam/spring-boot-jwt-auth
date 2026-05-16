package org.foam.springbootjwtauth.unit.aspect;

import org.foam.springbootjwtauth.aspect.LogMethodAspect;
import org.foam.springbootjwtauth.model.request.auth.LoginRequest;
import org.foam.springbootjwtauth.model.response.auth.CsrfResponse;
import org.foam.springbootjwtauth.model.response.auth.LoginResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.ObjectMapper;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LogMethodAspectUnitTests {

    private final LogMethodAspect logMethodAspect = new LogMethodAspect(new ObjectMapper());

    @Test
    void redactsSensitiveRequestFields() throws Exception {
        String serialized = serializeForLog(new LoginRequest("user", "password"));

        assertTrue(serialized.contains("\"username\":\"user\""));
        assertTrue(serialized.contains("\"password\":\"[REDACTED]\""));
        assertFalse(serialized.contains("\":\"password\""));
    }

    @Test
    void redactsSensitiveResponseBodyFields() throws Exception {
        ResponseEntity<LoginResponse> response = ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, "refreshToken=raw-refresh-token")
                .body(new LoginResponse("raw-access-token", "raw-refresh-token", "device-id"));

        String serialized = serializeForLog(response);

        assertTrue(serialized.contains("\"status\":200"));
        assertTrue(serialized.contains("\"accessToken\":\"[REDACTED]\""));
        assertTrue(serialized.contains("\"refreshToken\":\"[REDACTED]\""));
        assertTrue(serialized.contains("\"deviceId\":\"device-id\""));
        assertFalse(serialized.contains("raw-access-token"));
        assertFalse(serialized.contains("raw-refresh-token"));
        assertFalse(serialized.contains("Set-Cookie"));
    }

    @Test
    void redactsCsrfTokenResponseBody() throws Exception {
        String serialized = serializeForLog(ResponseEntity.ok(new CsrfResponse("raw-csrf-token", "X-XSRF-TOKEN")));

        assertTrue(serialized.contains("\"token\":\"[REDACTED]\""));
        assertTrue(serialized.contains("\"headerName\":\"X-XSRF-TOKEN\""));
        assertFalse(serialized.contains("raw-csrf-token"));
    }

    private String serializeForLog(Object value) throws Exception {
        Method serializeForLog = LogMethodAspect.class.getDeclaredMethod("serializeForLog", Object.class);
        serializeForLog.setAccessible(true);

        return (String) serializeForLog.invoke(logMethodAspect, value);
    }
}
