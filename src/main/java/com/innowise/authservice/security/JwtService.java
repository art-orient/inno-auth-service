package com.innowise.authservice.security;

import com.innowise.authservice.entity.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

/**
 * Service responsible for generating, parsing, and validating JWT tokens.
 * Provides functionality for issuing access and refresh tokens, extracting
 * claims, and verifying token expiration and integrity.
 *
 * <p>The service uses HMAC SHA‑256 signing and stores user-specific data
 * (ID, role, token type) inside JWT claims.</p>
 */
@Service
public class JwtService {

  private static final String CLAIM_USER_ID = "userId";
  private static final String CLAIM_ROLE = "role";
  private static final String CLAIM_TYPE = "type";
  private static final String ACCESS = "access";
  private static final String REFRESH = "refresh";

  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.access-expiration-ms}")
  private long accessExpirationMs;

  @Value("${jwt.refresh-expiration-ms}")
  private long refreshExpirationMs;

  /**
   * Generates a short-lived access token containing user ID, role,
   * and token type information.
   *
   * @param user the authenticated user
   * @return a signed JWT access token
   */
  public String generateAccessToken(AuthUser user) {
    return generateToken(
            Map.of(CLAIM_USER_ID, user.getId(),
                    CLAIM_ROLE, user.getRole().name(),
                    CLAIM_TYPE, ACCESS),
            accessExpirationMs);
  }

  /**
   * Generates a long-lived refresh token containing user ID, role,
   * and token type information.
   *
   * @param user the authenticated user
   * @return a signed JWT refresh token
   */
  public String generateRefreshToken(AuthUser user) {
    return generateToken(
            Map.of(CLAIM_USER_ID, user.getId(),
                    CLAIM_ROLE, user.getRole().name(),
                    CLAIM_TYPE, REFRESH),
            refreshExpirationMs);
  }

  /**
   * Extracts the user ID stored inside the token.
   *
   * @param token the JWT token
   * @return the user ID claim
   */
  public Long extractUserId(String token) {
    return extractAllClaims(token).get(CLAIM_USER_ID, Long.class);
  }

  /**
   * Extracts the user role stored inside the token.
   *
   * @param token the JWT token
   * @return the role claim
   */
  public String extractRole(String token) {
    return extractAllClaims(token).get(CLAIM_ROLE, String.class);
  }

  /**
   * Validates the token by checking its signature and expiration.
   *
   * @param token the JWT token to validate
   * @return {@code true} if the token is valid and not expired; otherwise {@code false}
   */
  public boolean isTokenValid(String token) {
    try {
      return isTokenNotExpired(token);
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Validates the refresh token by checking its type and expiration.
   *
   * @param token the JWT refresh token
   * @return {@code true} if the token is a valid refresh token; otherwise {@code false}
   */
  public boolean isRefreshTokenValid(String token) {
    try {
      Claims claims = extractAllClaims(token);
      return REFRESH.equals(claims.get(CLAIM_TYPE, String.class))
              && isTokenNotExpired(token);
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Generates a signed JWT token with the provided claims and expiration time.
   *
   * @param claims       the claims to include in the token
   * @param expirationMs token lifetime in milliseconds
   * @return a signed JWT token
   */
  private String generateToken(Map<String, Object> claims, long expirationMs) {
    Date now = new Date();
    Date expiration = new Date(now.getTime() + expirationMs);
    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
  }

  /**
   * Checks whether the token has not expired.
   *
   * @param token the JWT token
   * @return {@code true} if expiration date is in the future
   */
  private boolean isTokenNotExpired(String token) {
    Date expiration = extractClaim(token, Claims::getExpiration);
    return expiration.after(new Date());
  }

  /**
   * Extracts a specific claim from the token using a resolver function.
   *
   * @param token    the JWT token
   * @param resolver function used to extract a claim
   * @param <T>      the type of the extracted claim
   * @return the extracted claim value
   */
  private <T> T extractClaim(String token, Function<Claims, T> resolver) {
    Claims claims = extractAllClaims(token);
    return resolver.apply(claims);
  }

  /**
   * Parses the token and returns all claims stored inside it.
   *
   * @param token the JWT token
   * @return the parsed claims
   */
  private Claims extractAllClaims(String token) {
    return Jwts
            .parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
  }

  /**
   * Decodes the Base64 secret and returns the signing key used for HMAC SHA‑256.
   *
   * @return the signing key
   */
  private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}