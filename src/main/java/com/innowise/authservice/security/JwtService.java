package com.innowise.authservice.security;

import com.innowise.authservice.entity.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
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

  public String generateAccessToken(AuthUser user) {
    return generateToken(buildClaims(user, ACCESS), accessExpirationMs);
  }

  public String generateRefreshToken(AuthUser user) {
    return generateToken(buildClaims(user, REFRESH), refreshExpirationMs);
  }

  public Long extractUserId(String token) {
    return extractAllClaims(token).get(CLAIM_USER_ID, Long.class);
  }

  public String extractRole(String token) {
    return extractAllClaims(token).get(CLAIM_ROLE, String.class);
  }

  public boolean isTokenValid(String token) {
    try {
      return isTokenNotExpired(token);
    } catch (Exception e) {
      return false;
    }
  }

  public boolean isRefreshTokenValid(String token) {
    try {
      Claims claims = extractAllClaims(token);
      return REFRESH.equals(claims.get(CLAIM_TYPE, String.class))
              && isTokenNotExpired(token);
    } catch (Exception e) {
      return false;
    }
  }

  private String generateToken(Map<String, Object> claims, long expirationMs) {
    Date now = new Date();
    Date expiration = new Date(now.getTime() + expirationMs);
    String token = Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    log.info("AUTH-SERVICE GENERATED TOKEN: {}", token);
    log.info("IAT  (issued at): {} (ms={})", now, now.getTime());
    log.info("EXP  (expires)  : {} (ms={})", expiration, expiration.getTime());
    log.info("NOW  (container): {} (ms={})", new Date(), System.currentTimeMillis());
    log.info("EXP - NOW (ms)  : {}", expiration.getTime() - System.currentTimeMillis());
    return token;
  }

  private boolean isTokenNotExpired(String token) {
    Date expiration = extractClaim(token, Claims::getExpiration);
    return expiration.after(new Date());
  }

  private <T> T extractClaim(String token, Function<Claims, T> resolver) {
    Claims claims = extractAllClaims(token);
    return resolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts
            .parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
  }

  private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  private Map<String, Object> buildClaims(AuthUser user, String type) {
    return Map.of(
            CLAIM_USER_ID, user.getId(),
            CLAIM_ROLE, user.getRole().name(),
            CLAIM_TYPE, type
    );
  }
}