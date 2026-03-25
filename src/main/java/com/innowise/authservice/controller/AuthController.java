package com.innowise.authservice.controller;

import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.service.AuthUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthUserService authUserService;

  @PostMapping("/register")
  public ResponseEntity<Void> register(@RequestBody RegisterRequest request) {
    authUserService.register(request);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }

  @PostMapping("/login")
  public JwtResponse login(@RequestBody LoginRequest request) {
    return authUserService.login(request);
  }

  @PostMapping("/refresh")
  public JwtResponse refresh(@RequestBody String refreshToken) {
    return authUserService.refresh(refreshToken);
  }

  @PostMapping("/validate")
  public Long validate(@RequestBody String token) {
    return authUserService.validate(token);
  }
}