package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LogoutRequest(@NotBlank String refreshToken,
                            @NotBlank @Size(min = 3, max = 64) String username,
                            @NotBlank @Size(max = 64) String deviceId) {
    @Override
    public String toString() {
        return "LogoutRequest[refreshToken=<redacted>, username=" + username + ", deviceId=" + deviceId + "]";
    }
}
