package org.foam.springbootjwtauth.model.request.auth;

public record RegisterUserRequest(String username, String email, String password) {
}
