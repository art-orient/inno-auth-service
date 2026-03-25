package com.innowise.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Base class for entities that require automatic auditing of creation and update timestamps.
 * Uses Spring Data JPA auditing to populate {@code createdAt} and {@code updatedAt} fields
 * without manual intervention.
 *
 * <p>Classes extending this superclass inherit timestamp fields that are automatically
 * managed by {@link AuditingEntityListener}.</p>
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public class Auditable {

  /**
   * Timestamp indicating when the entity was created.
   * Set automatically and never updated.
   */
  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  /**
   * Timestamp indicating when the entity was last modified.
   * Updated automatically on each entity update.
   */
  @LastModifiedDate
  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  /**
   * Returns the creation timestamp of the entity.
   *
   * @return the creation time
   */
  public LocalDateTime getCreatedAt() {
    return createdAt;
  }

  /**
   * Returns the last modification timestamp of the entity.
   *
   * @return the last update time
   */
  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }
}