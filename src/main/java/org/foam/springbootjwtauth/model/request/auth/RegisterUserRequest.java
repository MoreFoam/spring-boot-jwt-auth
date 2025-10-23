package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;

public record RegisterUserRequest(@NotBlank String username,
                                  @NotBlank String email,
                                  @NotBlank String password) {
}
