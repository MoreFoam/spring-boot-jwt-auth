package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequest(@NotBlank String refreshToken,
                             @NotBlank @Size(min = 3, max = 64) String username,
                             @NotBlank @Size(max = 64) String deviceId) {
}
