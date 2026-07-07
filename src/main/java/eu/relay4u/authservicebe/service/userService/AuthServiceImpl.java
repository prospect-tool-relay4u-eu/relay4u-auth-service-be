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
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    @Value("${security.password.pepper}")
    private String pepper;

    @Value("${security.lockout.max-attempts}")
    private int maxAttempts;

    @Value("${security.lockout.duration-minutes}")
    private int lockoutDuration;

    @Value("${verification.code.expiry-minutes}")
    private int verificationCodeExpiryMinutes;

    @Value("${verification.code.max-attempts}")
    private int maxVerificationAttempts;

    @Value("${verification.resend.max-per-hour}")
    private int maxResendPerHour;


    @Override
    @Transactional
    public UserDto register(RegisterRequest request) {
        validRegisterData(request);

        User user = userMapper.toEntity(request);
        user.setPassword(passwordEncoder.encode(request.password() + pepper));
        user.setEmailVerified(false);
        user.setVerificationAttempts(0);
        user.setResendCount(0);

        String code = generateVerificationCode();
        user.setVerificationCode(hashVerificationCode(code));
        user.setVerificationCodeExpiry(LocalDateTime.now().plusMinutes(verificationCodeExpiryMinutes));

        userRepository.save(user);

        emailService.sendVerificationCode(user.getEmail(), user.getName(), code);

        return userMapper.toDto(user);
    }

    private void validRegisterData(RegisterRequest request) {
        if (!request.password().equals(request.confirmPassword())
                || userRepository.findUserByEmail(request.email()).isPresent()) {
            throw new RegisterException("Invalid register data");
        }
    }

    @Override
    @Transactional(noRollbackFor = {BadCredentialsException.class, LockedException.class, EmailNotVerifiedException.class})
    public AuthenticationResponse login(LoginRequest request) {
        User user = userRepository.findUserByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        isUserLocked(user);

        if (!Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new EmailNotVerifiedException("Account not verified. Check your email inbox.");
        }

        try {
            return getAuthenticationResponse(request, user);
        } catch (BadCredentialsException e) {
            handleFailedLogin(user);
            throw e;
        }
    }

    @Override
    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        User user = userRepository.findUserByEmail(request.email())
                .orElseThrow(() -> new InvalidVerificationCodeException("Invalid verification code."));

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new EmailAlreadyVerifiedException("Account is already verified.");
        }

        if (user.getVerificationAttempts() >= maxVerificationAttempts) {
            throw new VerificationBlockedException("Verification attempt limit exceeded. Please request a new code.");
        }

        if (user.getVerificationCodeExpiry() == null ||
                LocalDateTime.now().isAfter(user.getVerificationCodeExpiry())) {
            throw new VerificationCodeExpiredException("Verification code has expired. Please request a new code.");
        }

        String expectedHash = user.getVerificationCode();
        String actualHash = hashVerificationCode(request.code());
        if (!MessageDigest.isEqual(
                actualHash.getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8))) {
            user.setVerificationAttempts(user.getVerificationAttempts() + 1);
            userRepository.save(user);
            throw new InvalidVerificationCodeException("Invalid verification code.");
        }

        user.setEmailVerified(true);
        user.setVerificationCode(null);
        user.setVerificationCodeExpiry(null);
        user.setVerificationAttempts(0);
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void resendVerification(ResendVerificationRequest request) {
        User user = userRepository.findUserByEmail(request.email())
                .orElseThrow(() -> new RegisterException("Invalid credentials."));

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new EmailAlreadyVerifiedException("Account is already verified.");
        }

        LocalDateTime now = LocalDateTime.now();
        if (user.getLastResendAt() == null || user.getLastResendAt().isBefore(now.minusHours(1))) {
            user.setResendCount(0);
        }

        if (user.getResendCount() >= maxResendPerHour) {
            throw new ResendRateLimitException("Code sending limit exceeded. Try again in an hour.");
        }

        String code = generateVerificationCode();
        user.setVerificationCode(hashVerificationCode(code));
        user.setVerificationCodeExpiry(now.plusMinutes(verificationCodeExpiryMinutes));
        user.setVerificationAttempts(0);
        user.setResendCount(user.getResendCount() + 1);
        user.setLastResendAt(now);
        userRepository.save(user);

        emailService.sendVerificationCode(user.getEmail(), user.getName(), code);
    }

    private void isUserLocked(User user) {
        if (user.getAccountLocked()) {
            if (user.getLockTime().isBefore(LocalDateTime.now())) {
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
                userRepository.save(user);
            } else {
                throw new LockedException("Account is locked. Try again later.");
            }
        }
    }

    private @NonNull AuthenticationResponse getAuthenticationResponse(LoginRequest request, User user) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password() + pepper
                )
        );

        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        return new AuthenticationResponse(
                jwtUtil.generateToken(authenticate.getName())
        );
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= maxAttempts) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now().plusMinutes(lockoutDuration));
        }
        userRepository.save(user);
    }

    private String generateVerificationCode() {
        return String.format("%06d", new SecureRandom().nextInt(1_000_000));
    }

    private String hashVerificationCode(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(code.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
