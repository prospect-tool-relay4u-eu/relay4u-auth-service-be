package eu.relay4u.authservicebe.dto.verification;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyEmailRequest(
        @Email @NotBlank String email,
        @NotBlank @Pattern(regexp = "^\\d{6}$", message = "Code must consist of 6 digits") String code
) {}
