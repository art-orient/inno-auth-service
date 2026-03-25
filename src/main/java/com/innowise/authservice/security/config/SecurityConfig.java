package com.innowise.authservice.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;

/**
 * Security configuration for the authentication service. Defines HTTP security rules,
 * disables session state, configures CSRF behavior, and exposes security-related beans.
 *
 * <p>This configuration allows public access to authentication endpoints while keeping
 * the application stateless and ready for JWT-based authentication.</p>
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  /**
   * Configures the application's HTTP security settings, including:
   * <ul>
   *   <li>Disabling CSRF protection (suitable for stateless APIs)</li>
   *   <li>Enforcing stateless session management</li>
   *   <li>Allowing public access to authentication endpoints</li>
   *   <li>Permitting all other requests (delegated to API gateway or external filters)</li>
   * </ul>
   *
   * @param http the {@link HttpSecurity} builder
   * @return the configured {@link SecurityFilterChain}
   * @throws Exception if the security configuration fails
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                            "/api/auth/login",
                            "/api/auth/register",
                            "/api/auth/refresh",
                            "/api/auth/validate"
                    ).permitAll()
                    .anyRequest().permitAll()
            );
    return http.build();
  }

  /**
   * Provides a {@link PasswordEncoder} bean using BCrypt hashing algorithm.
   * Used for securely storing and verifying user passwords.
   *
   * @return a BCrypt-based password encoder
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}