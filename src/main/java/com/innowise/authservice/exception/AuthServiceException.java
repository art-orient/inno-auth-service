package com.innowise.authservice.exception;

/**
 * Base exception type for authentication-related errors within the auth service.
 * Used to signal failures such as invalid credentials, registration conflicts,
 * or other domain-specific authentication issues.
 */
public class AuthServiceException extends RuntimeException {

  /**
   * Creates a new exception without a detail message.
   */
  public AuthServiceException() {
    super();
  }

  /**
   * Creates a new exception with the specified detail message.
   *
   * @param message the description of the error
   */
  public AuthServiceException(String message) {
    super(message);
  }

  /**
   * Creates a new exception with the specified detail message and cause.
   *
   * @param message the description of the error
   * @param cause   the underlying cause of the exception
   */
  public AuthServiceException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates a new exception with the specified cause.
   *
   * @param cause the underlying cause of the exception
   */
  public AuthServiceException(Throwable cause) {
    super(cause);
  }
}
