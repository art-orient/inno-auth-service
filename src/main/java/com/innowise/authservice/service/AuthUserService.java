package com.innowise.authservice.service;

import com.innowise.authservice.dto.AuthUserDto;
import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.ValidateResponse;

import java.util.List;

/**
 * Service interface defining the core authentication operations of the auth module.
 * Provides functionality for user registration, login, token validation, and token refresh.
 * Implementations of this interface are responsible for interacting with the persistence layer
 * and generating or validating JWT tokens.
 */
public interface AuthUserService {

  /**
   * Registers a new authentication user using the provided credentials.
   * <p>
   * The method validates that the username is unique, encodes the password,
   * assigns a role (ADMIN or USER depending on bootstrap logic), activates the account,
   * persists the user entity, and returns the created user as a DTO.
   * <p>
   * This method is used as the first step in the distributed registration flow
   * (Saga pattern), therefore it must return the identifier of the newly created user
   * to allow further orchestration and potential rollback.
   *
   * @param request the registration data containing username and password
   * @return {@link AuthUserDto} containing the id, username, role, and active status
   */
  AuthUserDto register(RegisterRequest request);

  /**
   * Authenticates a user using the provided credentials and issues a pair of JWT tokens.
   *
   * @param request the login credentials containing username and password
   * @return a {@link JwtResponse} containing access and refresh tokens
   */
  JwtResponse login(LoginRequest request);

  /**
   * Validates an access token and extracts user identity information.
   *
   * @param token access token
   * @return user ID and role
   */
  ValidateResponse validate(String token);

  /**
   * Issues a new pair of JWT tokens using the provided refresh token.
   * Implementations must verify that the refresh token is valid and not expired.
   *
   * @param refreshToken the refresh token used to obtain new tokens
   * @return a {@link JwtResponse} containing newly generated access and refresh tokens
   */
  JwtResponse refresh(String refreshToken);

  /**
   * Returns all users. Accessible only to administrators.
   *
   * @return list of users
   */
  List<AuthUserDto> getAllUsers();

  /**
   * Activates a user account.
   *
   * @param id user identifier
   */
  void activateUser(Long id);

  /**
   * Deactivates a user account.
   *
   * @param id user identifier
   */
  void deactivateUser(Long id);

  /**
   * Permanently removes user authentication credentials.
   * <p>
   * This operation deletes the user's login data and associated authentication
   * records. It is typically used during system cleanup or as part of a
   * multi-service rollback sequence. Once deleted, the user cannot be restored.
   * </p>
   *
   * @param id the identifier of the user whose credentials should be removed
   */
  void delete(Long id);
}