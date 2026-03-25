package com.innowise.authservice.service;

import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;

public interface AuthUserService {

  void register(RegisterRequest request);

  JwtResponse login(LoginRequest request);

  Long validate(String token);

  JwtResponse refresh(String refreshToken);
}
