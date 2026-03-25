package com.innowise.authservice.service.impl;

import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.entity.AuthUser;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.mapper.AuthUserMapper;
import com.innowise.authservice.repository.AuthUserRepository;
import com.innowise.authservice.service.AuthUserService;
import com.innowise.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthUserServiceImpl implements AuthUserService {

  private final AuthUserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthUserMapper mapper;
  private static final String USER_NOT_FOUND = "User not found";
  private static final String USER_DEACTIVATED = "User is deactivated";
  private static final String INVALID_CREDENTIALS = "Invalid credentials";
  private static final String USERNAME_EXISTS = "Username already exists";
  private static final String INVALID_TOKEN = "Invalid token";

  @Override
  public void register(RegisterRequest request) {
    if (userRepository.existsByUsername(request.username())) {
      throw new AuthServiceException(USERNAME_EXISTS);
    }
    AuthUser user = mapper.toEntity(request);
    user.setPassword(passwordEncoder.encode(request.password()));
    user.setActive(true);
    boolean isFirstUser = userRepository.count() == 0;
    Role role = isFirstUser ? Role.ADMIN : Role.USER;
    user.setRole(role);
    userRepository.save(user);
  }

  @Override
  public JwtResponse login(LoginRequest request) {
    AuthUser user = findActiveUser(request.username());
    validatePassword(request.password(), user.getPassword());
    return generateTokens(user);
  }

  @Override
  public Long validate(String token) {
    if (!jwtService.isTokenValid(token)) {
      throw new AuthServiceException(INVALID_TOKEN);
    }
    return jwtService.extractUserId(token);
  }

  @Override
  public JwtResponse refresh(String refreshToken) {
    if (!jwtService.isRefreshTokenValid(refreshToken)) {
      throw new AuthServiceException(INVALID_TOKEN);
    }
    Long userId = jwtService.extractUserId(refreshToken);
    AuthUser user = userRepository.findById(userId)
            .orElseThrow(() -> new AuthServiceException(USER_NOT_FOUND));
    return generateTokens(user);
  }

  private AuthUser findActiveUser(String username) {
    AuthUser user = userRepository.findByUsername(username)
            .orElseThrow(() -> new AuthServiceException(USER_NOT_FOUND));
    if (!user.isActive()) {
      throw new AuthServiceException(USER_DEACTIVATED);
    }
    return user;
  }

  private void validatePassword(String rawPassword, String encodedPassword) {
    if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
      throw new AuthServiceException(INVALID_CREDENTIALS);
    }
  }

  private JwtResponse generateTokens(AuthUser user) {
    String accessToken = jwtService.generateAccessToken(user);
    String refreshToken = jwtService.generateRefreshToken(user);
    return new JwtResponse(accessToken, refreshToken);
  }
}
