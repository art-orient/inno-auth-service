package com.innowise.authservice.dto;

public record JwtResponse(String accessToken, String refreshToken) {
}
