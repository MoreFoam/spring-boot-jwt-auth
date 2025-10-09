package org.foam.springbootjwtauth.exception.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_FOUND, reason = "Refresh Token Not Found")
public class RefreshTokenNotFoundException extends RuntimeException {
    public RefreshTokenNotFoundException() {
        super("Refresh Token Not Found");
    }


    public RefreshTokenNotFoundException(String message) {
        super(message);
    }
}
