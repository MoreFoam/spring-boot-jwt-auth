package org.foam.springbootjwtauth.controller;

import org.foam.springbootjwtauth.exception.auth.RefreshTokenNotFoundException;
import org.foam.springbootjwtauth.exception.auth.UserAlreadyExistsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.NoSuchElementException;

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
                .status(HttpStatus.BAD_REQUEST)
                .body("Invalid refresh token.");
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<String> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
        logger.warn("User already exists: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body("Username or email already exists.");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        String message = ex.getMessage() == null || ex.getMessage().isBlank() ? "Bad request." : ex.getMessage();
        logger.warn("Bad request: {}", message);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(message);
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<String> handleJwtException(JwtException ex) {
        logger.warn("Invalid JWT: {}", ex.getClass().getSimpleName());

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body("Invalid token.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationException(MethodArgumentNotValidException ex) {
        String validationMessage = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fieldError -> "Validation failed for field [" + fieldError.getField() + "]: " + fieldError.getDefaultMessage())
                .orElse("Validation failed.");

        logger.warn(validationMessage);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(validationMessage);
    }

    @ExceptionHandler({NoSuchElementException.class, UsernameNotFoundException.class})
    public ResponseEntity<String> handleNotFoundException(Exception ex) {
        String message = ex.getMessage() == null || ex.getMessage().isBlank() ? "Resource not found." : ex.getMessage();
        logger.warn("Resource not found: {}", message);

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(message);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        logger.warn("Access denied.");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body("Access denied.");
    }
}
