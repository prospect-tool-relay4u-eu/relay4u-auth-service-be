package eu.relay4u.authservicebe.controller;

import eu.relay4u.authservicebe.dto.UserDto;
import eu.relay4u.authservicebe.dto.login.AuthenticationResponse;
import eu.relay4u.authservicebe.dto.login.LoginRequest;
import eu.relay4u.authservicebe.dto.register.RegisterRequest;
import eu.relay4u.authservicebe.dto.verification.ResendVerificationRequest;
import eu.relay4u.authservicebe.dto.verification.VerifyEmailRequest;
import eu.relay4u.authservicebe.service.userService.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock AuthService authService;

    @InjectMocks AuthController authController;

    @Test
    void register_returns201WithCreatedUser() {
        RegisterRequest request = new RegisterRequest("Jane Doe", "jane@example.com", "Passw0rd!", "Passw0rd!");
        UserDto userDto = new UserDto(1L, "Jane Doe", "jane@example.com", null);
        when(authService.register(request)).thenReturn(userDto);

        ResponseEntity<UserDto> response = authController.register(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isEqualTo(userDto);
    }

    @Test
    void login_returns200WithToken() {
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        AuthenticationResponse authResponse = new AuthenticationResponse("jwt-token");
        when(authService.login(request)).thenReturn(authResponse);

        ResponseEntity<AuthenticationResponse> response = authController.login(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(authResponse);
    }

    @Test
    void verifyEmail_returns200_andDelegatesToService() {
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "123456");

        ResponseEntity<Void> response = authController.verifyEmail(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(authService).verifyEmail(request);
    }

    @Test
    void resendVerification_returns200_andDelegatesToService() {
        ResendVerificationRequest request = new ResendVerificationRequest("jane@example.com");
        UserDto userDto = new UserDto(1L, "Jane Doe", "jane@example.com", null);
        when(authService.resendVerification(request)).thenReturn(userDto);

        ResponseEntity<UserDto> response = authController.resendVerification(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(userDto);
    }
}
