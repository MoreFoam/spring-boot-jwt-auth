package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;

public record WebTokenRequest(@NotBlank String username,
                              @NotBlank String deviceId) {
}
