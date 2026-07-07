package eu.relay4u.authservicebe.dto.register;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.Length;

public record RegisterRequest(
        @NotBlank
        String name,
        @Email
        @NotBlank
        String email,
        @NotBlank
        @Length(min = 8)
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&]).*$",
                message = "Password must contain at least one uppercase letter, one digit and one special character"
        )
        String password,
        @NotBlank
        @Length(min = 8)
        String confirmPassword
) {
}
