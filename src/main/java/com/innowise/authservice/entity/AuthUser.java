package com.innowise.authservice.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Entity representing a user authenticated and managed by the authentication service.
 * Stores credentials, role information, and activation status. Extends {@link Auditable}
 * to include metadata such as creation and modification timestamps.
 */
@Entity
@Table(name = "auth_user")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUser extends Auditable {

  /**
   * Primary identifier of the user. Generated automatically by the database.
   */
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /**
   * Unique username used for authentication. Must be non-null and unique.
   */
  @Column(nullable = false, unique = true)
  private String username;

  /**
   * Encrypted password stored in the database. Must be non-null.
   */
  @Column(nullable = false)
  private String password;

  /**
   * Role assigned to the user, defining access level within the system.
   */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Role role;

  /**
   * Indicates whether the user account is active. Inactive accounts cannot authenticate.
   */
  @Column(nullable = false)
  private boolean active = true;
}