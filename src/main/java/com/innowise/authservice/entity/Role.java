package com.innowise.authservice.entity;

/**
 * Enumeration of user roles supported by the authentication service.
 * Defines the authorization level assigned to a user within the system.
 */
public enum Role {
  /**
   * Administrative user with elevated privileges.
   */
  ADMIN,

  /**
   * Standard application user with basic access rights.
   */
  USER
}
