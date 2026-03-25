package com.innowise.authservice.dto;

/**
 * Response DTO containing a pair of JWT tokens issued after successful authentication
 * or token refresh. The {@code accessToken} is a short‑lived token used for
 * authorization in protected endpoints, while the {@code refreshToken} is a
 * long‑lived token used to obtain new access tokens without re-authentication.
 *
 * @param accessToken  JWT access token used for authenticated requests
 * @param refreshToken JWT refresh token used to renew access tokens
 */
public record JwtResponse(String accessToken, String refreshToken) {
}
