package com.innowise.authservice.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(AuthServiceException.class)
  public ResponseEntity<String> handleAuthServiceException(AuthServiceException ex) {
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ex.getMessage());
  }

  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<String> handleExpiredJwt(ExpiredJwtException ex) {
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Token expired");
  }

  @ExceptionHandler(SignatureException.class)
  public ResponseEntity<String> handleSignature(SignatureException ex) {
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Invalid token signature");
  }

  @ExceptionHandler(MalformedJwtException.class)
  public ResponseEntity<String> handleMalformed(MalformedJwtException ex) {
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Malformed token");
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<String> handleOther(Exception ex) {
    return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body("Internal error");
  }
}
