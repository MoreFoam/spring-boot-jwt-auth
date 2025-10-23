package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(@NotBlank String refreshToken,
                            @NotBlank String username,
                            @NotBlank String deviceId) {
}
