package com.innowise.authservice.security;

import com.innowise.authservice.entity.AuthUser;
import com.innowise.authservice.entity.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Field;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

  private JwtService jwtService;

  private final String secret = Base64.getEncoder()
          .encodeToString("super-secret-key-1234567890-1234567890-1234567890-123456".getBytes());

  @BeforeEach
  void setup() throws Exception {
    jwtService = new JwtService();
    setField(jwtService, "secret", secret);
    setField(jwtService, "accessExpirationMs", 1000 * 60);
    setField(jwtService, "refreshExpirationMs", 1000 * 60 * 60);
  }

  private void setField(Object target, String field, Object value) throws Exception {
    Field f = target.getClass().getDeclaredField(field);
    f.setAccessible(true);
    f.set(target, value);
  }

  private AuthUser createUser() {
    AuthUser user = new AuthUser();
    user.setId(10L);
    user.setRole(Role.ADMIN);
    return user;
  }

  @Test
  void generateAccessToken_containsCorrectClaims() {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    assertEquals(10L, jwtService.extractUserId(token));
    assertEquals("ADMIN", jwtService.extractRole(token));
    assertTrue(jwtService.isTokenValid(token));
  }

  @Test
  void generateRefreshToken_containsCorrectClaims() {
    AuthUser user = createUser();
    String token = jwtService.generateRefreshToken(user);
    assertEquals(10L, jwtService.extractUserId(token));
    assertEquals("ADMIN", jwtService.extractRole(token));
    assertTrue(jwtService.isRefreshTokenValid(token));
  }

  @Test
  void isTokenValid_validToken_returnsTrue() {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    assertTrue(jwtService.isTokenValid(token));
  }

  @Test
  void isTokenValid_invalidSignature_returnsFalse() throws Exception {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    setField(jwtService, "secret",
            Base64.getEncoder().encodeToString("another-secret".getBytes()));
    assertFalse(jwtService.isTokenValid(token));
  }

  @Test
  void isTokenValid_expiredToken_returnsFalse() throws Exception {
    AuthUser user = createUser();
    setField(jwtService, "accessExpirationMs", 1L);
    String token = jwtService.generateAccessToken(user);
    assertFalse(jwtService.isTokenValid(token));
  }

  @Test
  void isRefreshTokenValid_validRefreshToken_returnsTrue() {
    AuthUser user = createUser();
    String token = jwtService.generateRefreshToken(user);
    assertTrue(jwtService.isRefreshTokenValid(token));
  }

  @Test
  void isRefreshTokenValid_accessToken_returnsFalse() {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    assertFalse(jwtService.isRefreshTokenValid(token));
  }

  @Test
  void isRefreshTokenValid_expiredRefreshToken_returnsFalse() throws Exception {
    AuthUser user = createUser();
    setField(jwtService, "refreshExpirationMs", 1L);
    String token = jwtService.generateRefreshToken(user);
    assertFalse(jwtService.isRefreshTokenValid(token));
  }

  @Test
  void extractUserId_returnsCorrectValue() {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    assertEquals(10L, jwtService.extractUserId(token));
  }

  @Test
  void extractRole_returnsCorrectValue() {
    AuthUser user = createUser();
    String token = jwtService.generateAccessToken(user);
    assertEquals("ADMIN", jwtService.extractRole(token));
  }

  @Test
  void extractUserId_invalidToken_throws() {
    String invalid = "abc.def.ghi";
    assertThrows(Exception.class, () -> jwtService.extractUserId(invalid));
  }

  @Test
  void extractRole_invalidToken_throws() {
    String invalid = "abc.def.ghi";
    assertThrows(Exception.class, () -> jwtService.extractRole(invalid));
  }
}
