package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.dto.*;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = true)
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
            "c3VwZXItc2VjcmV0LWtleS0xMjM0NTY3ODkwLTEyMzQ1Njc4OTAtMTIzNDU2Nzg5MC0xMjM0NTY=");
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
    mockMvc.perform(post("/api/auth/credentials")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated());
    AuthUser user = userRepository.findByUsername("alex").orElseThrow();
    assertEquals(Role.ADMIN, user.getRole()); // first user = admin
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
    mockMvc.perform(post("/api/auth/credentials")
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
    RefreshTokenRequest refreshRequest = new RefreshTokenRequest(jwt.refreshToken());
    mockMvc.perform(post("/api/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(refreshRequest)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken", notNullValue()))
            .andExpect(jsonPath("$.refreshToken", notNullValue()));
  }

  @Test
  void validate_success_returnsUserInfo() throws Exception {
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
    mockMvc.perform(post("/api/auth/validate")
                    .header("Authorization", "Bearer " + jwt.accessToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userId").value(user.getId()))
            .andExpect(jsonPath("$.role").value("USER"));
  }

  @Test
  void getAllUsers_success() throws Exception {
    String token = loginAsAdmin();
    mockMvc.perform(get("/api/auth/users")
                    .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
  }

  @Test
  void activateUser_success() throws Exception {
    String token = loginAsAdmin();
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(false);
    userRepository.save(user);
    mockMvc.perform(post("/api/auth/users/" + user.getId() + "/activate")
              .header("Authorization", "Bearer " + token)
              .contentType(MediaType.APPLICATION_JSON))
              .andExpect(status().isOk());
    AuthUser updated = userRepository.findById(user.getId()).orElseThrow();
    assertTrue(updated.isActive());
  }

  @Test
  void deactivateUser_success() throws Exception {
    String token = loginAsAdmin();
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    mockMvc.perform(post("/api/auth/users/" + user.getId() + "/deactivate")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk());
    AuthUser updated = userRepository.findById(user.getId()).orElseThrow();
    assertFalse(updated.isActive());
  }

  private String loginAsAdmin() throws Exception {
    AuthUser admin = new AuthUser();
    admin.setUsername("admin");
    admin.setPassword(encoder.encode("pass"));
    admin.setRole(Role.ADMIN);
    admin.setActive(true);
    userRepository.save(admin);
    String loginResponse = mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new LoginRequest("admin", "pass"))))
            .andReturn()
            .getResponse()
            .getContentAsString();
    return objectMapper.readValue(loginResponse, JwtResponse.class).accessToken();
  }

  @Test
  void deleteUser_success_returns204() throws Exception {
    String token = loginAsAdmin();
    AuthUser user = new AuthUser();
    user.setUsername("alex");
    user.setPassword(encoder.encode("pass"));
    user.setRole(Role.USER);
    user.setActive(true);
    userRepository.save(user);
    mockMvc.perform(delete("/api/auth/" + user.getId())
                    .header("Authorization", "Bearer " + token))
            .andExpect(status().isNoContent());
    assertFalse(userRepository.findById(user.getId()).isPresent());
  }

  @Test
  void deleteUser_notFound_returns400() throws Exception {
    String token = loginAsAdmin();
    mockMvc.perform(delete("/api/auth/999")
                    .header("Authorization", "Bearer " + token))
            .andExpect(status().isBadRequest())
            .andExpect(content().string("User not found"));
  }
}