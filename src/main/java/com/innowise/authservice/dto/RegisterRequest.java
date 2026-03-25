package com.innowise.authservice.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO used for registering a new user in the system. Contains the
 * credentials required to create an account. Both fields are mandatory and
 * validated to ensure that blank or empty values are not accepted.
 *
 * @param username the desired username for the new account; must not be blank
 * @param password the raw password for the new account; must not be blank
 */
public record RegisterRequest(@NotBlank String username, @NotBlank String password) {
}
