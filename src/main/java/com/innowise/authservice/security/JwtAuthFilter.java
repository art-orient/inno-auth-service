package com.innowise.authservice.security;

import com.innowise.authservice.dto.ValidateResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

  private final JwtService jwtService;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain)
          throws ServletException, IOException {

    String header = request.getHeader("Authorization");
    if (header == null || !header.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    String token = header.substring(7);
    if (!jwtService.isTokenValid(token)) {
      filterChain.doFilter(request, response);
      return;
    }

    Long userId = jwtService.extractUserId(token);
    String role = jwtService.extractRole(token);
    ValidateResponse principal = new ValidateResponse(userId, role);
    UsernamePasswordAuthenticationToken auth =
      new UsernamePasswordAuthenticationToken(principal, null, List.of(() -> "ROLE_" + role));
    SecurityContextHolder.getContext().setAuthentication(auth);
    filterChain.doFilter(request, response);
  }
}
