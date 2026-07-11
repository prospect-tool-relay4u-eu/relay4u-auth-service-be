# `AuthController` — `/api/auth`

All endpoints are public (no JWT required — this is the service that issues them). Every endpoint delegates from `AuthController` straight into `AuthServiceImpl` (`service.userService`); the controller itself holds no business logic.

## Endpoints

| Method | Path | Request | Response | Status |
|---|---|---|---|---|
| POST | `/register` | `RegisterRequest{name, email, password, confirmPassword}` | `UserDto{id, name, email}` | 201 Created |
| POST | `/login` | `LoginRequest{email, password}` | `AuthenticationResponse{token}` | 200 OK |
| POST | `/verify-email` | `VerifyEmailRequest{email, code}` (code: 6 digits) | – | 200 OK |
| POST | `/resend-verification` | `ResendVerificationRequest{email}` | – | 200 OK |

Request validation (Bean Validation): `email` must be a valid email, `password` min length 8 and must contain an uppercase letter, a digit and a special character, `code` must match `^\d{6}$`.

**Registration does not return a token** — there is no auto-login. The client must call `/login` separately, and `/login` will reject unverified accounts (see below).

## Flow: register

```mermaid
sequenceDiagram
    participant C as AuthController
    participant S as AuthServiceImpl
    participant R as UserRepository
    participant E as EmailService

    C->>S: register(request)
    S->>S: validate password == confirmPassword
    S->>R: findUserByEmail(email)
    Note over S: throws RegisterException (400) if mismatch or email taken
    S->>S: hash password (Argon2 + pepper), generate 6-digit code, SHA-256 hash + expiry
    S->>R: save(new User, emailVerified=false)
    S->>E: sendVerificationCode(email, code)
    S-->>C: UserDto (201)
```

## Flow: login

The most complex flow — lockout state and email-verification state are both checked before credentials are even validated by Spring Security's `AuthenticationManager`.

```mermaid
sequenceDiagram
    participant C as AuthController
    participant S as AuthServiceImpl
    participant R as UserRepository
    participant AM as AuthenticationManager
    participant J as JwtUtil

    C->>S: login(request)
    S->>R: findUserByEmail(email)
    Note over S: throws BadCredentialsException (401) if not found
    S->>S: isUserLocked? (accountLocked && lockTime not yet passed)
    Note over S: throws LockedException (423) if still locked
    Note over S: if lock expired, auto-unlocks (accountLocked=false, failedLoginAttempts=0)
    S->>S: emailVerified?
    Note over S: throws EmailNotVerifiedException (403) if false
    S->>AM: authenticate(email, password)
    alt success
        AM-->>S: Authentication OK
        S->>R: reset failedLoginAttempts=0
        S->>J: generateToken(user)
        S-->>C: AuthenticationResponse{token} (200)
    else BadCredentialsException
        S->>R: increment failedLoginAttempts
        Note over S: if attempts >= 5: accountLocked=true, lockTime=now+10min
        S-->>C: rethrow BadCredentialsException (401)
    end
```

## Flow: verify-email

```mermaid
sequenceDiagram
    participant C as AuthController
    participant S as AuthServiceImpl
    participant R as UserRepository

    C->>S: verifyEmail(request)
    S->>R: findUserByEmail(email)
    Note over S: throws InvalidVerificationCodeException (400) if not found (avoids user enumeration)
    S->>S: already verified? -> EmailAlreadyVerifiedException (409)
    S->>S: verificationAttempts >= 5? -> VerificationBlockedException (423)
    S->>S: expiry passed or null? -> VerificationCodeExpiredException (400)
    S->>S: SHA-256(submitted code) == stored hash? (constant-time compare)
    alt match
        S->>R: emailVerified=true, clear code/expiry, verificationAttempts=0
        S-->>C: 200
    else mismatch
        S->>R: increment verificationAttempts
        S-->>C: throw InvalidVerificationCodeException (400)
    end
```

## Flow: resend-verification

Rate-limited to 3 resends per rolling hour (`verification.resend.max-per-hour`); the counter resets automatically once `lastResendAt` is more than an hour old.

```mermaid
sequenceDiagram
    participant C as AuthController
    participant S as AuthServiceImpl
    participant R as UserRepository
    participant E as EmailService

    C->>S: resendVerification(request)
    S->>R: findUserByEmail(email)
    Note over S: throws RegisterException (400) if not found
    S->>S: already verified? -> EmailAlreadyVerifiedException (409)
    S->>S: lastResendAt older than 1h? -> reset resendCount=0
    S->>S: resendCount >= 3? -> ResendRateLimitException (429)
    S->>S: generate new code, new hash+expiry, reset verificationAttempts=0
    S->>R: save(resendCount+1, lastResendAt=now)
    S->>E: sendVerificationCode(email, newCode)
    S-->>C: 200
```
