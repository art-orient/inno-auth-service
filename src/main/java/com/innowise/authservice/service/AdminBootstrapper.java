package com.innowise.authservice.service;

import com.innowise.authservice.repository.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AdminBootstrapper {

  private final AuthUserRepository userRepository;

  public boolean shouldAssignAdminRole() {
    return userRepository.count() == 0;
  }
}
