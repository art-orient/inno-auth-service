package com.innowise.authservice.exception;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DummyController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class GlobalExceptionHandlerTest {

  @Autowired
  private MockMvc mockMvc;

  @Test
  void handleMalformedJwt_returns401() throws Exception {
    mockMvc.perform(get("/test/malformed"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("Malformed token"));
  }

  @Test
  void handleAuthServiceException_returns400() throws Exception {
    mockMvc.perform(get("/test/auth"))
            .andExpect(status().isBadRequest())
            .andExpect(content().string("Auth error"));
  }

  @Test
  void handleJwtException_returns401() throws Exception {
    mockMvc.perform(get("/test/jwt"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("Invalid or expired token"));
  }

  @Test
  void handleOtherException_returns500() throws Exception {
    mockMvc.perform(get("/test/other"))
            .andExpect(status().isInternalServerError())
            .andExpect(content().string("Internal error"));
  }
}
