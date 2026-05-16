package org.foam.springbootjwtauth.exception.auth;

public class RefreshTokenNotFoundException extends RuntimeException {
    public RefreshTokenNotFoundException() {
        super("Refresh token not found");
    }


    public RefreshTokenNotFoundException(String message) {
        super(message);
    }
}
