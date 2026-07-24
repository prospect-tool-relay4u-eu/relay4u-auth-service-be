package eu.relay4u.authservicebe.service.userService;

import eu.relay4u.authservicebe.dto.UserDto;
import eu.relay4u.authservicebe.dto.login.AuthenticationResponse;
import eu.relay4u.authservicebe.dto.login.LoginRequest;
import eu.relay4u.authservicebe.dto.register.RegisterRequest;
import eu.relay4u.authservicebe.dto.verification.ResendVerificationRequest;
import eu.relay4u.authservicebe.dto.verification.VerifyEmailRequest;
import jakarta.validation.Valid;

public interface AuthService {
    UserDto register(@Valid RegisterRequest request);

    AuthenticationResponse login(@Valid LoginRequest request);

    void verifyEmail(@Valid VerifyEmailRequest request);

    UserDto resendVerification(@Valid ResendVerificationRequest request);
}
