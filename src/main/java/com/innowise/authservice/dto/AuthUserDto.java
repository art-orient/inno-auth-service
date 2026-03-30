package com.innowise.authservice.dto;

public record AuthUserDto(Long id, String username, String role, boolean active) {
}
