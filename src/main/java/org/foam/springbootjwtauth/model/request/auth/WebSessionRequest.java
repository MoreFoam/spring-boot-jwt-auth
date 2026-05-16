package org.foam.springbootjwtauth.model.request.auth;

import jakarta.validation.constraints.NotBlank;

public record WebSessionRequest(@NotBlank String username,
                                @NotBlank String deviceId) {
}
