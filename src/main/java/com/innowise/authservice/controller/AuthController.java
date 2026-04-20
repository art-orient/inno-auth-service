package com.innowise.authservice.controller;

import com.innowise.authservice.dto.AuthUserDto;
import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RefreshTokenRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.ValidateResponse;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.service.AuthUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

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
  @PostMapping("/credentials")
  public ResponseEntity<AuthUserDto> register(@RequestBody RegisterRequest request) {
    AuthUserDto created = authUserService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(created);
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
   * @param request the request containing the refresh token
   * @return a {@link JwtResponse} containing newly generated access and refresh tokens
   */
  @PostMapping("/refresh")
  public JwtResponse refresh(@RequestBody RefreshTokenRequest request) {
    return authUserService.refresh(request.refreshToken());
  }

  /**
   * Validates a JWT access token provided in the Authorization header.
   * <p>
   * Expected header format: {@code Authorization: Bearer <token>}.
   * If the header is missing or does not contain a Bearer token,
   * an {@link AuthServiceException} is thrown.
   *
   * @param authorizationHeader the Authorization header containing the Bearer token
   * @return user identity information extracted from the validated token
   * @throws AuthServiceException if the header is missing, malformed, or the token is invalid
   */
  @PostMapping("/validate")
  public ValidateResponse validate(@RequestHeader("Authorization") String authorizationHeader) {
    if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
      throw new AuthServiceException("Missing or invalid Authorization header");
    }
    String token = authorizationHeader.replace("Bearer ", "");
    return authUserService.validate(token);
  }

  /**
   * Returns a list of all users. Accessible only to administrators.
   *
   * @return list of users with basic identity information
   */
  @GetMapping("/users")
  @PreAuthorize("hasRole('ADMIN')")
  public List<AuthUserDto> getAllUsers() {
    return authUserService.getAllUsers();
  }

  /**
   * Activates a user account. Accessible only to administrators.
   *
   * @param id identifier of the user to activate
   */
  @PostMapping("/users/{id}/activate")
  @PreAuthorize("hasRole('ADMIN')")
  public void activateUser(@PathVariable Long id) {
    authUserService.activateUser(id);
  }

  /**
   * Deactivates a user account. Accessible only to administrators.
   *
   * @param id identifier of the user to deactivate
   */
  @PostMapping("/users/{id}/deactivate")
  @PreAuthorize("hasRole('ADMIN')")
  public void deactivateUser(@PathVariable Long id) {
    authUserService.deactivateUser(id);
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    authUserService.delete(id);
    return ResponseEntity.noContent().build();
  }
}