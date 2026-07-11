# Documentation index — relay4u-auth-service-be

Detailed developer/tester documentation for the auth microservice. The root [`README.md`](../README.md) covers setup and a quick reference; these pages go deeper into request flow, call chains and error handling.

## What this service does

Owns the full account lifecycle for the Relay4U prospecting tool: registration, password hashing, account lockout, email verification (6-digit code), and RS256 JWT issuance. Other services (like `eu-relay-4u-prospecting-be`) never see a password — they validate JWTs independently via this service's JWKS endpoint.

## Package structure

| Package | Responsibility |
|---|---|
| `controller` | `AuthController` (`/api/auth`), `JwksController` (`/.well-known/jwks.json`) |
| `service.userService` | `AuthService` / `AuthServiceImpl` — registration, login, verification business logic |
| `service.email` | `EmailService` interface, `ResendEmailService` (production), `LoggingEmailService` (sandbox) |
| `dto` | Request/response records, grouped by `login`, `register`, `verification` |
| `mapper` | `UserMapper` (MapStruct) |
| `model` | `User` (implements `UserDetails`, soft-delete via `@SQLDelete`/`@SQLRestriction`) |
| `repository` | `UserRepository` |
| `security` | `JwtUtil` (signing/keys), `JwtAuthFilter`, `CustomUserDetailsService` |
| `exception` | Custom exceptions + `GlobalExceptionHandler` |
| `configuration` | Security, CORS, MapStruct, Swagger configuration |

## Running locally

```bash
./mvnw spring-boot:run
```

Requires PostgreSQL (`eu_relay_4u_auth_service` database). Set `server.port` if you need this on a specific port alongside `eu-relay-4u-prospecting-be` (which defaults to expecting this service at `:8081`).

## Contents

- [`architecture.md`](architecture.md) — JWT signing/JWKS, account lockout and email-verification lifecycle rules
- [`endpoints/auth.md`](endpoints/auth.md) — `AuthController`: register, login, verify-email, resend-verification
- [`endpoints/jwks.md`](endpoints/jwks.md) — `JwksController`
- [`exceptions.md`](exceptions.md) — exception → HTTP status mapping
