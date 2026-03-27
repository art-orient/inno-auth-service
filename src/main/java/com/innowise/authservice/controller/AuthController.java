package com.innowise.authservice.controller;

import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.service.AuthUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller providing authentication-related endpoints such as user registration,
 * login, token refresh, and token validation. Delegates all business logic to
 * {@link AuthUserService}, acting as a thin transport layer between HTTP requests
 * and the authentication service.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthUserService authUserService;

  /**
   * Registers a new user using the provided registration data.
   * Returns HTTP 201 (Created) on successful registration.
   *
   * @param request the registration data containing username and password
   * @return an empty response with HTTP status 201
   */
  @PostMapping("/register")
  public ResponseEntity<Void> register(@RequestBody RegisterRequest request) {
    authUserService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }

  /**
   * Authenticates a user using the provided credentials and returns a pair of JWT tokens.
   *
   * @param request the login credentials containing username and password
   * @return a {@link JwtResponse} containing access and refresh tokens
   */
  @PostMapping("/login")
  public JwtResponse login(@RequestBody LoginRequest request) {
    return authUserService.login(request);
  }

  /**
   * Issues a new pair of JWT tokens using the provided refresh token.
   *
   * @param refreshToken the refresh token used to obtain new tokens
   * @return a {@link JwtResponse} containing newly generated access and refresh tokens
   */
  @PostMapping("/refresh")
  public JwtResponse refresh(@RequestBody String refreshToken) {
    return authUserService.refresh(refreshToken);
  }

  /**
   * Validates a JWT access token provided in the Authorization header.
   * <p>
   * Expected header format: {@code Authorization: Bearer <token>}.
   * If the header is missing or does not contain a Bearer token,
   * an {@link AuthServiceException} is thrown.
   *
   * @param authorizationHeader the Authorization header containing the Bearer token
   * @return the user ID extracted from the validated token
   * @throws AuthServiceException if the header is missing, malformed, or the token is invalid
   */
  @PostMapping("/validate")
  public Long validate(@RequestHeader("Authorization") String authorizationHeader) {
    if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
      throw new AuthServiceException("Missing or invalid Authorization header");
    }
    String token = authorizationHeader.replace("Bearer ", "");
    return authUserService.validate(token);
  }
}