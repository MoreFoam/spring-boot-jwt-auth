package org.foam.springbootjwtauth.controller;

import org.foam.springbootjwtauth.exception.auth.RefreshTokenNotFoundException;
import org.foam.springbootjwtauth.exception.auth.UserAlreadyExistsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Handle any uncaught exception
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        logger.error("Unhandled exception: ", ex);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Internal server error.");
    }

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<String> handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex) {
        logger.warn("Refresh token not found.");

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body("Refresh token not found.");
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<String> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
        logger.warn("User already exists: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body("User already exists.");
    }

    @ExceptionHandler({IllegalArgumentException.class, JwtException.class, MethodArgumentNotValidException.class})
    public ResponseEntity<String> handleBadRequestException(Exception ex) {
        logger.warn("Bad request: {}", ex.getClass().getSimpleName());

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body("Bad request.");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        logger.warn("Access denied.");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Access denied.");
    }
}
