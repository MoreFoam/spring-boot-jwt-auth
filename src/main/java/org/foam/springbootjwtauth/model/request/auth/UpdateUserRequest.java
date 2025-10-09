package org.foam.springbootjwtauth.model.request.auth;

public record UpdateUserRequest(
        Long id,
        String username,
        String email) {
}
