package org.foam.springbootjwtauth.model.request.auth;

public record LogoutRequest(String refreshToken, String username, String deviceId) {
}
