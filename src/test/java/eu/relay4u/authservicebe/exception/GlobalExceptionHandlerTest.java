package eu.relay4u.authservicebe.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    // --- Happy path ---

    @Test
    void handleAccessDenied_returns403() {
        ProblemDetail result = handler.handleAccessDenied(new AccessDeniedException("Forbidden"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(result.getProperties()).containsEntry("code", ErrorCode.ACCESS_DENIED.name());
    }

    @Test
    void handleValidation_returns400WithErrorsMapAndCode() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError error = new FieldError("obj", "name", "must not be blank");

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(error));

        ProblemDetail result = handler.handleValidation(ex);

        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getProperties()).containsEntry("code", ErrorCode.VALIDATION_FAILED.name());
        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) result.getProperties().get("errors");
        assertThat(errors).containsEntry("name", "must not be blank");
    }

    @Test
    void handleIllegalArgument_returns400WithMessage() {
        ProblemDetail result = handler.handleIllegalArgument(new IllegalArgumentException("bad input"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).isEqualTo("bad input");
    }

    @Test
    void handleBadCredentials_returns401WithGenericMessage() {
        ProblemDetail result = handler.handleBadCredentials(new BadCredentialsException("leaked detail"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(result.getDetail()).isEqualTo("Invalid credentials");
        assertThat(result.getProperties()).containsEntry("code", ErrorCode.INVALID_CREDENTIALS.name());
    }

    @Test
    void handleLocked_returns423WithMessage() {
        ProblemDetail result = handler.handleLocked(new LockedException("Account is locked. Try again later."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.LOCKED.value());
        assertThat(result.getDetail()).isEqualTo("Account is locked. Try again later.");
    }

    @Test
    void handleRegister_returns400WithMessage() {
        ProblemDetail result = handler.handleRegister(new RegisterException("Invalid register data"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).isEqualTo("Invalid register data");
    }

    @Test
    void handleEmailAlreadyRegistered_returns409WithMessage() {
        ProblemDetail result = handler.handleEmailAlreadyRegistered(
                new EmailAlreadyRegisteredException("An account with this email already exists."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
        assertThat(result.getDetail()).isEqualTo("An account with this email already exists.");
    }

    @Test
    void handleEmailNotVerified_returns403WithMessage() {
        ProblemDetail result = handler.handleEmailNotVerified(new EmailNotVerifiedException("Account not verified."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(result.getDetail()).isEqualTo("Account not verified.");
    }

    @Test
    void handleEmailAlreadyVerified_returns409WithMessage() {
        ProblemDetail result = handler.handleEmailAlreadyVerified(new EmailAlreadyVerifiedException("Already verified."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
        assertThat(result.getDetail()).isEqualTo("Already verified.");
    }

    @Test
    void handleInvalidVerificationCode_returns400WithMessage() {
        ProblemDetail result = handler.handleInvalidVerificationCode(new InvalidVerificationCodeException("Invalid code."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).isEqualTo("Invalid code.");
    }

    @Test
    void handleVerificationCodeExpired_returns400WithMessage() {
        ProblemDetail result = handler.handleVerificationCodeExpired(new VerificationCodeExpiredException("Code expired."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).isEqualTo("Code expired.");
    }

    @Test
    void handleVerificationBlocked_returns423WithMessage() {
        ProblemDetail result = handler.handleVerificationBlocked(new VerificationBlockedException("Blocked."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.LOCKED.value());
        assertThat(result.getDetail()).isEqualTo("Blocked.");
    }

    @Test
    void handleResendRateLimit_returns429WithMessage() {
        ProblemDetail result = handler.handleResendRateLimit(new ResendRateLimitException("Too many resends."));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
        assertThat(result.getDetail()).isEqualTo("Too many resends.");
    }

    @Test
    void handlePasswordNotSet_returns428WithEmailAndName() {
        ProblemDetail result = handler.handlePasswordNotSet(new PasswordNotSetException("jane@example.com", "Jane Doe"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.PRECONDITION_REQUIRED.value());
        assertThat(result.getProperties()).containsEntry("email", "jane@example.com");
        assertThat(result.getProperties()).containsEntry("name", "Jane Doe");
    }

    @Test
    void handleUnexpected_returns500WithGenericDetailAndInternalErrorCode() {
        ProblemDetail result = handler.handleUnexpected(new RuntimeException("db connection refused"));

        assertThat(result.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(result.getProperties()).containsEntry("code", ErrorCode.INTERNAL_ERROR.name());
        assertThat(result.getDetail()).doesNotContain("db connection refused");
    }

    // --- Edge cases ---

    @Test
    void handleValidation_withMultipleFieldErrors_includesAll() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(
                new FieldError("obj", "name", "must not be blank"),
                new FieldError("obj", "email", "must be a valid email")
        ));

        ProblemDetail result = handler.handleValidation(ex);

        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) result.getProperties().get("errors");
        assertThat(errors).hasSize(2)
                .containsEntry("name", "must not be blank")
                .containsEntry("email", "must be a valid email");
    }

    @Test
    void handleValidation_withNullDefaultMessage_usesPlaceholder() {
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError errorWithNullMessage = new FieldError("obj", "field", null, false, null, null, null);

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(errorWithNullMessage));

        ProblemDetail result = handler.handleValidation(ex);

        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) result.getProperties().get("errors");
        assertThat(errors.get("field")).isEqualTo("invalid");
    }
}
