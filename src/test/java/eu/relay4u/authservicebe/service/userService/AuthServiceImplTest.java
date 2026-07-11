package eu.relay4u.authservicebe.service.userService;

import eu.relay4u.authservicebe.dto.UserDto;
import eu.relay4u.authservicebe.dto.login.AuthenticationResponse;
import eu.relay4u.authservicebe.dto.login.LoginRequest;
import eu.relay4u.authservicebe.dto.register.RegisterRequest;
import eu.relay4u.authservicebe.dto.verification.ResendVerificationRequest;
import eu.relay4u.authservicebe.dto.verification.VerifyEmailRequest;
import eu.relay4u.authservicebe.exception.*;
import eu.relay4u.authservicebe.mapper.UserMapper;
import eu.relay4u.authservicebe.model.User;
import eu.relay4u.authservicebe.repository.UserRepository;
import eu.relay4u.authservicebe.security.JwtUtil;
import eu.relay4u.authservicebe.service.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock UserRepository userRepository;
    @Mock UserMapper userMapper;
    @Mock org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    @Mock AuthenticationManager authenticationManager;
    @Mock JwtUtil jwtUtil;
    @Mock EmailService emailService;

    @InjectMocks AuthServiceImpl authService;

    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "pepper", "pepper123");
        ReflectionTestUtils.setField(authService, "maxAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockoutDuration", 10);
        ReflectionTestUtils.setField(authService, "verificationCodeExpiryMinutes", 15);
        ReflectionTestUtils.setField(authService, "maxVerificationAttempts", 5);
        ReflectionTestUtils.setField(authService, "maxResendPerHour", 3);

        user = new User();
        user.setId(1L);
        user.setEmail("jane@example.com");
        user.setName("Jane Doe");
        user.setPassword("encoded-existing-password");
        user.setEmailVerified(true);
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setVerificationAttempts(0);
        user.setResendCount(0);
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ==================== register ====================

    @Test
    void register_savesUserAndSendsVerificationCode() {
        RegisterRequest request = new RegisterRequest("Jane Doe", "jane@example.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.empty());
        when(userMapper.toEntity(request)).thenReturn(user);
        when(passwordEncoder.encode("Passw0rd!pepper123")).thenReturn("encoded-password");
        when(userMapper.toDto(user)).thenReturn(new UserDto(1L, "Jane Doe", "jane@example.com"));

        UserDto result = authService.register(request);

        assertThat(result.email()).isEqualTo("jane@example.com");
        assertThat(user.getPassword()).isEqualTo("encoded-password");
        assertThat(user.getEmailVerified()).isFalse();
        verify(userRepository).save(user);
        verify(emailService).sendVerificationCode(eq("jane@example.com"), eq("Jane Doe"), any());
    }

    @Test
    void register_throwsRegisterException_whenPasswordsDoNotMatch() {
        RegisterRequest request = new RegisterRequest("Jane Doe", "jane@example.com", "Passw0rd!", "Different1!");

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(RegisterException.class);
        verifyNoInteractions(userMapper, emailService);
    }

    @Test
    void register_throwsEmailAlreadyRegisteredException_whenActiveVerifiedAccountExists() {
        RegisterRequest request = new RegisterRequest("Jane Doe", "jane@example.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    @Test
    void register_throwsEmailAlreadyRegisteredException_whenPendingClaimHasNotExpired() {
        user.setEmailVerified(false);
        user.setVerificationCodeExpiry(LocalDateTime.now().plusMinutes(10));
        RegisterRequest request = new RegisterRequest("Jane Doe", "jane@example.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    @Test
    void register_allowsReclaim_whenExistingRegistrationIsAbandonedAndExpired() {
        user.setEmailVerified(false);
        user.setVerificationCodeExpiry(LocalDateTime.now().minusMinutes(1));
        RegisterRequest request = new RegisterRequest("New Owner", "jane@example.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("Passw0rd!pepper123")).thenReturn("encoded-password");
        when(userMapper.toDto(user)).thenReturn(new UserDto(1L, "New Owner", "jane@example.com"));

        UserDto result = authService.register(request);

        assertThat(result.email()).isEqualTo("jane@example.com");
        assertThat(user.getName()).isEqualTo("New Owner");
        verify(userRepository).save(user);
        verify(userMapper, never()).toEntity(any(RegisterRequest.class));
    }

    @Test
    void register_throwsResendRateLimitException_whenReclaimingTooManyTimesWithinHour() {
        user.setEmailVerified(false);
        user.setVerificationCodeExpiry(LocalDateTime.now().minusMinutes(1));
        user.setResendCount(3);
        user.setLastResendAt(LocalDateTime.now().minusMinutes(10));
        RegisterRequest request = new RegisterRequest("New Owner", "jane@example.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(ResendRateLimitException.class);
    }

    @Test
    void register_completesSetup_whenExistingUserHasNullPassword() {
        user.setPassword(null);
        RegisterRequest request = new RegisterRequest("Jane Updated", "jane@example.com", "NewPassw0rd!", "NewPassw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("NewPassw0rd!pepper123")).thenReturn("encoded-new-password");
        when(userMapper.toDto(user)).thenReturn(new UserDto(1L, "Jane Updated", "jane@example.com"));

        UserDto result = authService.register(request);

        assertThat(result.email()).isEqualTo("jane@example.com");
        assertThat(user.getName()).isEqualTo("Jane Updated");
        assertThat(user.getPassword()).isEqualTo("encoded-new-password");
        assertThat(user.getEmailVerified()).isFalse();
        verify(userRepository).save(user);
        verify(userMapper, never()).toEntity(any(RegisterRequest.class));
        verify(emailService).sendVerificationCode(eq("jane@example.com"), eq("Jane Updated"), any());
    }

    // ==================== login ====================

    @Test
    void login_returnsToken_onValidCredentials() {
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
        when(jwtUtil.generateToken(user)).thenReturn("jwt-token");

        AuthenticationResponse response = authService.login(request);

        assertThat(response.token()).isEqualTo("jwt-token");
        assertThat(user.getFailedLoginAttempts()).isZero();
        verify(userRepository).save(user);
    }

    @Test
    void login_throwsPasswordNotSetException_whenPasswordIsNull() {
        user.setPassword(null);
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(PasswordNotSetException.class);

        verifyNoInteractions(authenticationManager);
    }

    @Test
    void login_throwsBadCredentialsException_whenUserNotFound() {
        LoginRequest request = new LoginRequest("missing@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void login_throwsEmailNotVerifiedException_whenAccountNotVerified() {
        user.setEmailVerified(false);
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(EmailNotVerifiedException.class);
    }

    @Test
    void login_throwsLockedException_whenAccountCurrentlyLocked() {
        user.setAccountLocked(true);
        user.setLockTime(LocalDateTime.now().plusMinutes(5));
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(LockedException.class);
    }

    @Test
    void login_unlocksAccount_whenLockDurationHasPassed() {
        user.setAccountLocked(true);
        user.setLockTime(LocalDateTime.now().minusMinutes(1));
        user.setFailedLoginAttempts(5);
        LoginRequest request = new LoginRequest("jane@example.com", "Passw0rd!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
        when(jwtUtil.generateToken(user)).thenReturn("jwt-token");

        AuthenticationResponse response = authService.login(request);

        assertThat(response.token()).isEqualTo("jwt-token");
        assertThat(user.getAccountLocked()).isFalse();
    }

    @Test
    void login_incrementsFailedAttempts_onBadCredentials() {
        user.setFailedLoginAttempts(2);
        LoginRequest request = new LoginRequest("jane@example.com", "WrongPassword!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad creds"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(3);
        assertThat(user.getAccountLocked()).isFalse();
        verify(userRepository).save(user);
    }

    @Test
    void login_locksAccount_whenMaxFailedAttemptsReached() {
        user.setFailedLoginAttempts(4);
        LoginRequest request = new LoginRequest("jane@example.com", "WrongPassword!");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad creds"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(5);
        assertThat(user.getAccountLocked()).isTrue();
        assertThat(user.getLockTime()).isNotNull();
    }

    // ==================== verifyEmail ====================

    @Test
    void verifyEmail_marksAccountVerified_onCorrectCode() {
        user.setEmailVerified(false);
        user.setVerificationCode(sha256Hex("123456"));
        user.setVerificationCodeExpiry(LocalDateTime.now().plusMinutes(10));
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "123456");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        authService.verifyEmail(request);

        assertThat(user.getEmailVerified()).isTrue();
        assertThat(user.getVerificationCode()).isNull();
        assertThat(user.getVerificationCodeExpiry()).isNull();
        verify(userRepository).save(user);
    }

    @Test
    void verifyEmail_throwsInvalidVerificationCodeException_whenUserNotFound() {
        VerifyEmailRequest request = new VerifyEmailRequest("missing@example.com", "123456");
        when(userRepository.findUserByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail(request))
                .isInstanceOf(InvalidVerificationCodeException.class);
    }

    @Test
    void verifyEmail_throwsEmailAlreadyVerifiedException_whenAlreadyVerified() {
        user.setEmailVerified(true);
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "123456");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.verifyEmail(request))
                .isInstanceOf(EmailAlreadyVerifiedException.class);
    }

    @Test
    void verifyEmail_throwsVerificationBlockedException_whenAttemptLimitExceeded() {
        user.setEmailVerified(false);
        user.setVerificationAttempts(5);
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "123456");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.verifyEmail(request))
                .isInstanceOf(VerificationBlockedException.class);
    }

    @Test
    void verifyEmail_throwsVerificationCodeExpiredException_whenCodeExpired() {
        user.setEmailVerified(false);
        user.setVerificationCodeExpiry(LocalDateTime.now().minusMinutes(1));
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "123456");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.verifyEmail(request))
                .isInstanceOf(VerificationCodeExpiredException.class);
    }

    @Test
    void verifyEmail_incrementsAttemptsAndThrows_whenCodeIncorrect() {
        user.setEmailVerified(false);
        user.setVerificationCode(sha256Hex("123456"));
        user.setVerificationCodeExpiry(LocalDateTime.now().plusMinutes(10));
        user.setVerificationAttempts(1);
        VerifyEmailRequest request = new VerifyEmailRequest("jane@example.com", "999999");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.verifyEmail(request))
                .isInstanceOf(InvalidVerificationCodeException.class);

        assertThat(user.getVerificationAttempts()).isEqualTo(2);
        verify(userRepository).save(user);
    }

    // ==================== resendVerification ====================

    @Test
    void resendVerification_sendsNewCode_andIncrementsCount() {
        user.setEmailVerified(false);
        user.setResendCount(0);
        ResendVerificationRequest request = new ResendVerificationRequest("jane@example.com");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        authService.resendVerification(request);

        assertThat(user.getResendCount()).isEqualTo(1);
        assertThat(user.getVerificationAttempts()).isZero();
        verify(userRepository).save(user);
        verify(emailService).sendVerificationCode(eq("jane@example.com"), eq("Jane Doe"), any());
    }

    @Test
    void resendVerification_throwsRegisterException_whenUserNotFound() {
        ResendVerificationRequest request = new ResendVerificationRequest("missing@example.com");
        when(userRepository.findUserByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resendVerification(request))
                .isInstanceOf(RegisterException.class);
    }

    @Test
    void resendVerification_throwsEmailAlreadyVerifiedException_whenAlreadyVerified() {
        user.setEmailVerified(true);
        ResendVerificationRequest request = new ResendVerificationRequest("jane@example.com");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.resendVerification(request))
                .isInstanceOf(EmailAlreadyVerifiedException.class);
    }

    @Test
    void resendVerification_throwsResendRateLimitException_whenLimitExceededWithinHour() {
        user.setEmailVerified(false);
        user.setResendCount(3);
        user.setLastResendAt(LocalDateTime.now().minusMinutes(10));
        ResendVerificationRequest request = new ResendVerificationRequest("jane@example.com");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.resendVerification(request))
                .isInstanceOf(ResendRateLimitException.class);
    }

    @Test
    void resendVerification_resetsCount_whenLastResendWasOverAnHourAgo() {
        user.setEmailVerified(false);
        user.setResendCount(3);
        user.setLastResendAt(LocalDateTime.now().minusHours(2));
        ResendVerificationRequest request = new ResendVerificationRequest("jane@example.com");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        authService.resendVerification(request);

        assertThat(user.getResendCount()).isEqualTo(1);
    }
}
