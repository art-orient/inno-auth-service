package com.innowise.authservice.exception;

import io.jsonwebtoken.MalformedJwtException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class DummyController {

  @GetMapping(value = "/malformed", produces = MediaType.TEXT_PLAIN_VALUE)
  public void throwMalformed() {
    throw new MalformedJwtException("Malformed");
  }

  @GetMapping(value = "/auth", produces = MediaType.TEXT_PLAIN_VALUE)
  public void throwAuth() {
    throw new AuthServiceException("Auth error");
  }

  @GetMapping(value = "/jwt", produces = MediaType.TEXT_PLAIN_VALUE)
  public void throwJwt() {
    throw new io.jsonwebtoken.JwtException("JWT error");
  }

  @GetMapping(value = "/other", produces = MediaType.TEXT_PLAIN_VALUE)
  public void throwOther() {
    throw new RuntimeException("Unexpected");
  }
}
