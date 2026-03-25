package com.innowise.authservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Configuration class enabling JPA auditing across the application.
 * Activates automatic population of auditing fields such as
 * {@code createdAt} and {@code updatedAt} in entities extending
 * {@link com.innowise.authservice.entity.Auditable}.
 */
@Configuration
@EnableJpaAuditing
public class JpaConfig {
}
