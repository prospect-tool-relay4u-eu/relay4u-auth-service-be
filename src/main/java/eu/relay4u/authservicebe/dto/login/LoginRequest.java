package eu.relay4u.authservicebe.dto.login;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

public record LoginRequest(
        @NotBlank
        @Email
        String email,
        @NotBlank
        @Length(min = 8)
        String password
) {
}
