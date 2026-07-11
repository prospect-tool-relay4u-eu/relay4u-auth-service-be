# Exceptions and error responses

`exception/GlobalExceptionHandler.java` returns RFC-7807 `ProblemDetail` JSON bodies (`type`, `title`, `status`, `detail`, `instance`; validation errors add a non-standard `errors` map).

## Exception → HTTP status

| Exception | Status | Thrown from |
|---|---|---|
| `RegisterException` | 400 Bad Request | `register` (password/confirmPassword mismatch); `resendVerification` (user not found) |
| `EmailAlreadyRegisteredException` | 409 Conflict | `register` (email belongs to a verified account, or an unverified one whose code hasn't expired yet — not eligible for reclaim) |
| `PasswordNotSetException` | 428 Precondition Required | `login` (account has `password = NULL` — manually migrated/abandoned; body includes `email`/`name` so the client can redirect into registration) |
| `BadCredentialsException` (Spring) | 401 Unauthorized | `login` (user not found, or wrong password) |
| `LockedException` (Spring) | 423 Locked | `login` (account currently locked out) |
| `EmailNotVerifiedException` | 403 Forbidden | `login` (account exists but email not yet verified) |
| `EmailAlreadyVerifiedException` | 409 Conflict | `verifyEmail`, `resendVerification` (account already verified) |
| `InvalidVerificationCodeException` | 400 Bad Request | `verifyEmail` (user not found — avoids user enumeration — or wrong code) |
| `VerificationCodeExpiredException` | 400 Bad Request | `verifyEmail` (no code pending, or expiry has passed) |
| `VerificationBlockedException` | 423 Locked | `verifyEmail` (too many wrong-code attempts on the current code) |
| `ResendRateLimitException` | 429 Too Many Requests | `resendVerification` (more than 3 resends in the last rolling hour); `register` (more than 3 reclaim attempts/hour on an abandoned, unverified registration) |
| `MethodArgumentNotValidException` (Spring) | 400 Bad Request (+ `errors` map) | Any endpoint — Bean Validation failures on the request body |
| `IllegalArgumentException` | 400 Bad Request | Generic fallback (not currently thrown by any auth flow) |
| `AccessDeniedException` (Spring) | 403 Forbidden | Generic Spring Security (not currently triggered — all `/api/auth/**` endpoints are public) |

## Known dead code

`ProjectNotFoundException` and `FieldKeyConflictException` exist in the `exception` package and are wired into `GlobalExceptionHandler` (404 / 409 respectively), but are **not thrown anywhere** in this service — they're leftover from a shared exception-handler template copied from the prospecting monolith. Safe to remove; kept here only as a heads-up in case future code (unrelated to auth) starts using them.
