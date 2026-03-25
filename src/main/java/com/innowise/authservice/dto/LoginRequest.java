package com.innowise.authservice.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO used for user authentication. Contains the credentials required
 * to perform a login attempt. Both fields are mandatory and validated to ensure
 * that empty or blank values are not accepted.
 *
 * @param username the username provided by the client; must not be blank
 * @param password the raw password provided by the client; must not be blank
 */
public record LoginRequest(@NotBlank String username, @NotBlank String password) {
}
