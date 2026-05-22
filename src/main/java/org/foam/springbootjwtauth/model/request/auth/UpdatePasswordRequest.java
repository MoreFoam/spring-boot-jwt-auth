package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdatePasswordRequest(@NotNull Long id,
                                    @NotBlank String currentPassword,
                                    @NotBlank @Size(min = 8, max = 128) String newPassword) {
    @Override
    public String toString() {
        return "UpdatePasswordRequest[id=" + id + ", currentPassword=<redacted>, newPassword=<redacted>]";
    }
}
