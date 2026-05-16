package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(@NotNull Long id,
                                @NotBlank @Size(min = 3, max = 64) String username,
                                @NotBlank @Email @Size(max = 254) String email) {
}
