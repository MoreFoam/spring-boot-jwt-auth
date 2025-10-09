package org.foam.springbootjwtauth.model.request.auth;

public record RefreshRequest(String refreshToken, String username, String deviceId) {
}
