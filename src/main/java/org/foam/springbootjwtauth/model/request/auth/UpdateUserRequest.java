package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record UpdateUserRequest(@NotNull Long id,
                                @NotBlank String username,
                                @NotBlank String email) {
}
