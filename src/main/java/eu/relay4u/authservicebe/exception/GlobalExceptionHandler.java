package eu.relay4u.authservicebe.exception;

import eu.relay4u.authservicebe.filter.CorrelationIdFilter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private ProblemDetail buildProblem(HttpStatus status, ErrorCode code, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty("code", code.name());
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (correlationId != null) {
            problem.setProperty("correlationId", correlationId);
        }
        return problem;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        fe -> fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "invalid",
                        (existing, duplicate) -> existing + "; " + duplicate
                ));
        log.info("Validation failed: {}", errors);
        ProblemDetail problem = buildProblem(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED, "Validation failed");
        problem.setProperty("errors", errors);
        return problem;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Bad request: {}", ex.getMessage());
        return buildProblem(HttpStatus.BAD_REQUEST, ErrorCode.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex) {
        log.info("Login attempt with invalid credentials");
        return buildProblem(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Invalid credentials");
    }

    @ExceptionHandler(LockedException.class)
    public ProblemDetail handleLocked(LockedException ex) {
        log.warn("Account locked: {}", ex.getMessage());
        return buildProblem(HttpStatus.LOCKED, ErrorCode.ACCOUNT_LOCKED, ex.getMessage());
    }

    @ExceptionHandler(RegisterException.class)
    public ProblemDetail handleRegister(RegisterException ex) {
        log.info("Register error: {}", ex.getMessage());
        return buildProblem(HttpStatus.BAD_REQUEST, ErrorCode.REGISTER_INVALID, ex.getMessage());
    }

    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    public ProblemDetail handleEmailAlreadyRegistered(EmailAlreadyRegisteredException ex) {
        log.info("Register conflict: {}", ex.getMessage());
        return buildProblem(HttpStatus.CONFLICT, ErrorCode.EMAIL_ALREADY_REGISTERED, ex.getMessage());
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ProblemDetail handleEmailNotVerified(EmailNotVerifiedException ex) {
        log.info("Login blocked, email not verified");
        return buildProblem(HttpStatus.FORBIDDEN, ErrorCode.EMAIL_NOT_VERIFIED, ex.getMessage());
    }

    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ProblemDetail handleEmailAlreadyVerified(EmailAlreadyVerifiedException ex) {
        log.info("Email already verified: {}", ex.getMessage());
        return buildProblem(HttpStatus.CONFLICT, ErrorCode.EMAIL_ALREADY_VERIFIED, ex.getMessage());
    }

    @ExceptionHandler(InvalidVerificationCodeException.class)
    public ProblemDetail handleInvalidVerificationCode(InvalidVerificationCodeException ex) {
        log.info("Invalid verification code submitted");
        return buildProblem(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_VERIFICATION_CODE, ex.getMessage());
    }

    @ExceptionHandler(VerificationCodeExpiredException.class)
    public ProblemDetail handleVerificationCodeExpired(VerificationCodeExpiredException ex) {
        log.info("Verification code expired");
        return buildProblem(HttpStatus.BAD_REQUEST, ErrorCode.VERIFICATION_CODE_EXPIRED, ex.getMessage());
    }

    @ExceptionHandler(VerificationBlockedException.class)
    public ProblemDetail handleVerificationBlocked(VerificationBlockedException ex) {
        log.warn("Verification blocked: {}", ex.getMessage());
        return buildProblem(HttpStatus.LOCKED, ErrorCode.VERIFICATION_BLOCKED, ex.getMessage());
    }

    @ExceptionHandler(ResendRateLimitException.class)
    public ProblemDetail handleResendRateLimit(ResendRateLimitException ex) {
        log.warn("Resend rate limit exceeded: {}", ex.getMessage());
        return buildProblem(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.RESEND_RATE_LIMIT, ex.getMessage());
    }

    @ExceptionHandler(PasswordNotSetException.class)
    public ProblemDetail handlePasswordNotSet(PasswordNotSetException ex) {
        log.info("Login attempt on passwordless account");
        ProblemDetail problem = buildProblem(HttpStatus.PRECONDITION_REQUIRED, ErrorCode.PASSWORD_NOT_SET, ex.getMessage());
        problem.setProperty("email", ex.getEmail());
        problem.setProperty("name", ex.getName());
        return problem;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return buildProblem(HttpStatus.FORBIDDEN, ErrorCode.ACCESS_DENIED, ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception ex) {
        log.error("Unhandled exception", ex);
        return buildProblem(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR,
                "An unexpected error occurred. Please try again later.");
    }
}
