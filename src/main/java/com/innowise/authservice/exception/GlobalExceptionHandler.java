package com.innowise.authservice.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Global exception handler for the authentication service. Centralizes the handling
 * of domain-specific and JWT-related exceptions, ensuring consistent HTTP responses
 * and structured logging across the application.
 *
 * <p>Each method maps a specific exception type to an appropriate HTTP status code
 * and a human-readable error message.</p>
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  /**
   * Handles domain-specific authentication errors such as invalid credentials
   * or registration conflicts.
   *
   * @param ex the thrown {@link AuthServiceException}
   * @return HTTP 400 with the exception message
   */
  @ExceptionHandler(AuthServiceException.class)
  public ResponseEntity<String> handleAuthServiceException(AuthServiceException ex) {
    log.warn("AuthServiceException: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ex.getMessage());
  }

  /**
   * Handles expired JWT tokens.
   *
   * @param ex the thrown {@link ExpiredJwtException}
   * @return HTTP 401 with a fixed "Token expired" message
   */
  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<String> handleExpiredJwt(ExpiredJwtException ex) {
    log.warn("Expired JWT token: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Token expired");
  }

  /**
   * Handles malformed JWT tokens, typically caused by corrupted or invalid token format.
   *
   * @param ex the thrown {@link MalformedJwtException}
   * @return HTTP 401 with a fixed "Malformed token" message
   */
  @ExceptionHandler(MalformedJwtException.class)
  public ResponseEntity<String> handleMalformed(MalformedJwtException ex) {
    log.warn("Malformed JWT token: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Malformed token");
  }

  /**
   * Handles generic JWT-related errors such as invalid signatures or tampered tokens.
   *
   * @param ex the thrown {@link JwtException}
   * @return HTTP 401 with a generic "Invalid or expired token" message
   */
  @ExceptionHandler(JwtException.class)
  public ResponseEntity<String> handleJwtErrors(JwtException ex) {
    log.warn("JWT error: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Invalid or expired token");
  }

  /**
   * Handles all unexpected exceptions not covered by more specific handlers.
   * Ensures that the application never exposes stack traces or internal details
   * to the client.
   *
   * @param ex the thrown exception
   * @return HTTP 500 with a generic "Internal error" message
   */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<String> handleOther(Exception ex) {
    log.error("Unexpected error: {}", ex.getMessage(), ex);
    return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body("Internal error");
  }
}