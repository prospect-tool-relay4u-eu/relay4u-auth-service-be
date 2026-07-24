package eu.relay4u.authservicebe.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserDto(
        Long id,
        String name,
        String email,
        String verificationCode
) {
}
