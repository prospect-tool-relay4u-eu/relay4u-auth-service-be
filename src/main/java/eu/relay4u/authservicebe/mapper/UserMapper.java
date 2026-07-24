package eu.relay4u.authservicebe.mapper;

import eu.relay4u.authservicebe.configuration.MapperConfig;
import eu.relay4u.authservicebe.dto.UserDto;
import eu.relay4u.authservicebe.dto.login.LoginRequest;
import eu.relay4u.authservicebe.dto.register.RegisterRequest;
import eu.relay4u.authservicebe.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(config = MapperConfig.class)
public interface UserMapper {
    User toEntity(UserDto dto);

    User toEntity(RegisterRequest request);

    User toEntity(LoginRequest request);

    @Mapping(target = "verificationCode", ignore = true)
    UserDto toDto(User entity);
}
