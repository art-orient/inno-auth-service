package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.AuthUserDto;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.entity.AuthUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface AuthUserMapper {

  @Mapping(target = "id", ignore = true)
  @Mapping(target = "role", ignore = true)
  @Mapping(target = "active", ignore = true)
  @Mapping(target = "password", ignore = true)
  AuthUser toEntity(RegisterRequest dto);

  AuthUserDto toDto(AuthUser user);
}
