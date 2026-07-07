package eu.relay4u.authservicebe.dto.verification;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ResendVerificationRequest(
        @Email @NotBlank String email
) {}
