package com.innowise.authservice.repository;

import com.innowise.authservice.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository interface for accessing and managing {@link AuthUser} entities.
 * Provides standard CRUD operations and additional lookup methods used by the
 * authentication service.
 */
public interface AuthUserRepository extends JpaRepository<AuthUser, Long> {

  /**
   * Retrieves a user by their unique username.
   *
   * @param username the username to search for
   * @return an {@link Optional} containing the user if found, or empty otherwise
   */
  Optional<AuthUser> findByUsername(String username);

  /**
   * Checks whether a user with the given username exists.
   *
   * @param username the username to check
   * @return {@code true} if a user with the given username exists, otherwise {@code false}
   */
  boolean existsByUsername(String username);

  /**
   * Returns the total number of users stored in the database.
   *
   * @return the number of user records
   */
  long count();
}
