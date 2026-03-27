package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.dto.JwtResponse;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.entity.AuthUser;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.AuthUserRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@ActiveProfiles("test")
class AuthIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> postgres =
          new PostgreSQLContainer<>(DockerImageName.parse("postgres:16"))
                  .withDatabaseName("authdb")
                  .withUsername("test")
                  .withPassword("test");

  @DynamicPropertySource
  static void registerProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
    registry.add("jwt.secret", () ->
            "c3VwZXItc2VjcmV0LWtleS0xMjM0NTY3ODkwLTEyMzQ1Njc4OTAtMTIzNDU2Nzg5MC0xMjM0NTY="
    );
    registry.add("jwt.access-expiration-ms", () -> "60000");
    registry.add("jwt.refresh-expiration-ms", () -> "3600000");
  }

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private AuthUserRepository userRepository;

  @Autowired
  private ObjectMapper objectMapper;

  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  @BeforeAll
  static void checkDocker() {
    Assumptions.assumeTrue(
            DockerClientFactory.instance().isDockerAvailable(),
            "Skipping integration tests because Docker is not available"
    );
  }

  @AfterEach
  void clean() {
    userRepository.deleteAll();
  }

  @Test
  void register_success_createsUser() throws Exception {
    RegisterRequest request = new RegisterRequest("alex", "pass");
    mockMvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated());
    AuthUser user = userRepository.findByUsername("alex").orElseThrow();
    assertEquals(Role.ADMIN, user.getRole());
  }

  @Test
  void register_duplicateUsername_returns400() throws Exception {
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    RegisterRequest request = new RegisterRequest("alex", "pass");
    mockMvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(content().string("Username already exists"));
  }

  @Test
  void login_success_returnsTokens() throws Exception {
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    LoginRequest request = new LoginRequest("alex", "pass");
    mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken", notNullValue()))
            .andExpect(jsonPath("$.refreshToken", notNullValue()));
  }

  @Test
  void refresh_success_returnsNewTokens() throws Exception {
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    String loginResponse = mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new LoginRequest("alex", "pass"))))
            .andReturn()
            .getResponse()
            .getContentAsString();
    JwtResponse jwt = objectMapper.readValue(loginResponse, JwtResponse.class);
    String refreshToken = jwt.refreshToken();
    mockMvc.perform(post("/api/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(refreshToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken", notNullValue()))
            .andExpect(jsonPath("$.refreshToken", notNullValue()));
  }

  @Test
  void validate_success_returnsUserId() throws Exception {
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    String loginResponse = mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new LoginRequest("alex", "pass"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

    JwtResponse jwt = objectMapper.readValue(loginResponse, JwtResponse.class);
    String accessToken = jwt.accessToken();
    mockMvc.perform(post("/api/auth/validate")
                    .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(content().string(String.valueOf(user.getId())));
  }
}