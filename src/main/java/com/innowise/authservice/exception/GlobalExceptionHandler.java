package com.innowise.authservice.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(AuthServiceException.class)
  public ResponseEntity<String> handleAuthServiceException(AuthServiceException ex) {
    log.warn("AuthServiceException: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ex.getMessage());
  }

  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<String> handleExpiredJwt(ExpiredJwtException ex) {
    log.warn("Expired JWT token: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Token expired");
  }

  @ExceptionHandler(MalformedJwtException.class)
  public ResponseEntity<String> handleMalformed(MalformedJwtException ex) {
    log.warn("Malformed JWT token: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Malformed token");
  }

  @ExceptionHandler(JwtException.class)
  public ResponseEntity<String> handleJwtErrors(JwtException ex) {
    log.warn("JWT error: {}", ex.getMessage());
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Invalid or expired token");
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<String> handleOther(Exception ex) {
    log.error("Unexpected error: {}", ex.getMessage(), ex);
    return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body("Internal error");
  }
}
