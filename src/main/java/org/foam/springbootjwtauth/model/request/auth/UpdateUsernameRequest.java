package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdateUsernameRequest(@NotNull Long id,
                                    @NotBlank @Size(min = 3, max = 64) String username,
                                    @NotBlank String currentPassword) {
    @Override
    public String toString() {
        return "UpdateUsernameRequest[id=" + id + ", username=" + username + ", currentPassword=<redacted>]";
    }
}
