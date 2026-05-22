package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record RegisterUserRequest(@NotBlank @Size(min = 3, max = 64) String username,
                                  @NotBlank @Email @Size(max = 254) String email,
                                  @NotBlank @Size(min = 8, max = 128) String password) {
    @Override
    public String toString() {
        return "RegisterUserRequest[username=" + username + ", email=" + email + ", password=<redacted>]";
    }
}
