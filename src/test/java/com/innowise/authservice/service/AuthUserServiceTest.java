package com.innowise.authservice.service;

import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.entity.AuthUser;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.mapper.AuthUserMapper;
import com.innowise.authservice.repository.AuthUserRepository;
import com.innowise.authservice.security.JwtService;
import com.innowise.authservice.service.impl.AuthUserServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthUserServiceImplTest {

  @Mock
  private AuthUserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private JwtService jwtService;

  @Mock
  private AuthUserMapper mapper;

  @Mock
  private AdminBootstrapper adminBootstrapper;

  @InjectMocks
  private AuthUserServiceImpl service;

  @BeforeEach
  void setup() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void register_success_firstUserGetsAdminRole() {
    RegisterRequest request = new RegisterRequest("alex", "pass");
    when(userRepository.existsByUsername("alex")).thenReturn(false);
    when(adminBootstrapper.shouldAssignAdminRole()).thenReturn(true);
    AuthUser mapped = new AuthUser();
    mapped.setUsername("alex");
    when(mapper.toEntity(request)).thenReturn(mapped);
    when(passwordEncoder.encode("pass")).thenReturn("hashed");
    when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    service.register(request);
    assertEquals("hashed", mapped.getPassword());
    assertTrue(mapped.isActive());
    assertEquals(Role.ADMIN, mapped.getRole());
  }

  @Test
  void register_success_nextUsersGetUserRole() {
    RegisterRequest request = new RegisterRequest("alex", "pass");
    when(userRepository.existsByUsername("alex")).thenReturn(false);
    when(adminBootstrapper.shouldAssignAdminRole()).thenReturn(false);
    AuthUser mapped = new AuthUser();
    mapped.setUsername("alex");
    when(mapper.toEntity(request)).thenReturn(mapped);
    when(passwordEncoder.encode("pass")).thenReturn("hashed");
    when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    service.register(request);
    assertEquals(Role.USER, mapped.getRole());
  }

  @Test
  void register_usernameExists_throws() {
    RegisterRequest request = new RegisterRequest("alex", "pass");
    when(userRepository.existsByUsername("alex")).thenReturn(true);
    assertThrows(AuthServiceException.class, () -> service.register(request));
    verify(userRepository, never()).save(any());
  }

  @Test
  void login_success() {
    LoginRequest request = new LoginRequest("alex", "pass");
    AuthUser user = new AuthUser();
    user.setId(1L);
    user.setUsername("alex");
    user.setPassword("hashed");
    user.setActive(true);
    when(userRepository.findByUsername("alex")).thenReturn(Optional.of(user));
    when(passwordEncoder.matches("pass", "hashed")).thenReturn(true);
    when(jwtService.generateAccessToken(user)).thenReturn("access");
    when(jwtService.generateRefreshToken(user)).thenReturn("refresh");
    JwtResponse response = service.login(request);
    assertEquals("access", response.accessToken());
    assertEquals("refresh", response.refreshToken());
  }

  @Test
  void login_userNotFound_throws() {
    LoginRequest request = new LoginRequest("alex", "pass");
    when(userRepository.findByUsername("alex")).thenReturn(Optional.empty());
    assertThrows(AuthServiceException.class, () -> service.login(request));
  }

  @Test
  void login_userDeactivated_throws() {
    LoginRequest request = new LoginRequest("alex", "pass");
    AuthUser user = new AuthUser();
    user.setActive(false);
    when(userRepository.findByUsername("alex")).thenReturn(Optional.of(user));
    assertThrows(AuthServiceException.class, () -> service.login(request));
  }

  @Test
  void login_invalidPassword_throws() {
    LoginRequest request = new LoginRequest("alex", "pass");
    AuthUser user = new AuthUser();
    user.setPassword("hashed");
    user.setActive(true);
    when(userRepository.findByUsername("alex")).thenReturn(Optional.of(user));
    when(passwordEncoder.matches("pass", "hashed")).thenReturn(false);
    assertThrows(AuthServiceException.class, () -> service.login(request));
  }

  @Test
  void validate_success() {
    when(jwtService.isTokenValid("token")).thenReturn(true);
    when(jwtService.extractUserId("token")).thenReturn(10L);
    Long id = service.validate("token");
    assertEquals(10L, id);
  }

  @Test
  void validate_invalidToken_throws() {
    when(jwtService.isTokenValid("token")).thenReturn(false);
    assertThrows(AuthServiceException.class, () -> service.validate("token"));
  }

  @Test
  void refresh_success() {
    AuthUser user = new AuthUser();
    user.setId(1L);
    when(jwtService.isRefreshTokenValid("refresh")).thenReturn(true);
    when(jwtService.extractUserId("refresh")).thenReturn(1L);
    when(userRepository.findById(1L)).thenReturn(Optional.of(user));
    when(jwtService.generateAccessToken(user)).thenReturn("newAccess");
    when(jwtService.generateRefreshToken(user)).thenReturn("newRefresh");
    JwtResponse response = service.refresh("refresh");
    assertEquals("newAccess", response.accessToken());
    assertEquals("newRefresh", response.refreshToken());
  }

  @Test
  void refresh_invalidToken_throws() {
    when(jwtService.isRefreshTokenValid("refresh")).thenReturn(false);
    assertThrows(AuthServiceException.class, () -> service.refresh("refresh"));
  }

  @Test
  void refresh_userNotFound_throws() {
    when(jwtService.isRefreshTokenValid("refresh")).thenReturn(true);
    when(jwtService.extractUserId("refresh")).thenReturn(1L);
    when(userRepository.findById(1L)).thenReturn(Optional.empty());
    assertThrows(AuthServiceException.class, () -> service.refresh("refresh"));
  }
}