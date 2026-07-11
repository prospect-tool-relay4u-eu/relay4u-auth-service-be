# Relay4U Auth Service

Standalone authentication microservice for the Relay4U prospecting tool. Handles registration, login, email verification and JWT issuance for [`eu-relay-4u-prospecting-be`](https://github.com/prospect-tool-relay4u-eu/prospect-tool-be) (and any other service that trusts its JWKS endpoint).

## Overview

This service owns the full account lifecycle: registration, password hashing, account lockout, 6-digit email verification codes, and signing JWTs that other services validate independently (asymmetric RS256, no shared secret). It does not know about projects, records, or any other business domain — see [`documentation/`](documentation/README.md) for details.

## Tech stack

- **Java 21**, **Spring Boot 4.1.0**, built with the Maven Wrapper (`./mvnw`)
- **PostgreSQL**
- **Spring Security**, Argon2/BCrypt-style password hashing with a server-side pepper
- **jjwt** + **nimbus-jose-jwt** for RS256 JWT signing and JWKS publishing
- **MapStruct** for entity/DTO mapping
- **Resend** for transactional email (verification codes) — swappable for a logging stub in the `sandbox` profile
- **Springdoc/Swagger UI** for interactive API docs

## Getting started

**Prerequisites:** JDK 21.

Configure the environment variables below (a local `.env` file is picked up automatically via `spring.config.import`), then run:

```bash
./mvnw spring-boot:run
```

By default the app starts on port `8080`; set `server.port` (e.g. via `.env`) if running alongside `eu-relay-4u-prospecting-be`, which by default expects this service at `http://localhost:8081`.

## Configuration / environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | PostgreSQL connection | local dev defaults provided |
| `SPRING_PROFILES_ACTIVE` | Active Spring profile | `sandbox` |
| `JWT_ISSUER` | `iss` claim on issued JWTs | `https://auth.relay4u.eu` |
| `JWT_PRIVATE_KEY` | PEM-encoded RSA private key for signing JWTs | if unset, an ephemeral key is generated at startup (fine for local dev, **not for production** — restarts invalidate all issued tokens) |
| `PASSWORD_PEPPER` | Server-side pepper mixed into password hashing | dev default provided — override in production |
| `RESEND_API_KEY` / `RESEND_FROM_EMAIL` | Resend transactional email | required unless using the `sandbox` profile |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:4200` |

See [`documentation/architecture.md`](documentation/architecture.md) for the account-lockout and email-verification lifecycle constants (max attempts, expiry, rate limits).

## API reference

Full interactive docs at `/swagger-ui.html` — **disabled in the `prod` profile** (`springdoc.api-docs.enabled=false` / `springdoc.swagger-ui.enabled=false`), so it's only available locally/sandbox. Summary — see [`documentation/endpoints/`](documentation/README.md) for exact DTOs, status codes and sequence diagrams.

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Register a new user, emails a verification code |
| POST | `/api/auth/login` | Authenticate and receive a JWT |
| POST | `/api/auth/verify-email` | Confirm email with a 6-digit code |
| POST | `/api/auth/resend-verification` | Resend the verification code (rate-limited) |
| GET | `/.well-known/jwks.json` | Public JWKS document, used by other services to validate issued JWTs |

## Account recovery ("reclaim") for password-less accounts

Accounts manually migrated with `password = NULL` (a safety-net path, not exposed through any endpoint) are handled specially:

- **Login** on such an account returns `428 Precondition Required` (`PasswordNotSetException`) with the account's `email`/`name` in the response body, instead of a normal `401`. Consumers (e.g. the FE) use this to redirect the user into the registration flow to set a password.
- **Registering again** with that same email is allowed and reuses the existing row (rather than failing with a "duplicate email" error) if the account has `password = NULL`, or if a previous registration was abandoned and its verification code has since expired (`EmailAlreadyRegisteredException` → `409` otherwise). Reclaim attempts on an abandoned-but-not-yet-expired registration are rate-limited the same way as verification-code resends.

See [`documentation/architecture.md`](documentation/architecture.md) and [`documentation/endpoints/auth.md`](documentation/endpoints/auth.md) for the full lifecycle and exact status codes.

## Sandbox profile

`SPRING_PROFILES_ACTIVE=sandbox` swaps real email delivery for a `LoggingEmailService`, which logs verification codes to the console instead of sending real emails — useful for local development and the project's pentest Docker sandbox.

## Docker

```bash
docker build -t relay4u-auth-service-be .
docker run -p 8081:8080 --env-file .env relay4u-auth-service-be
```

Multi-stage build (`maven` → `eclipse-temurin:21-jre-alpine`), exposes port `8080` internally. The runtime image drops root and runs as a dedicated non-root `appuser`/`appgroup`.

## Documentation

See [`documentation/README.md`](documentation/README.md) for the full endpoint-by-endpoint flow documentation, architecture, and error handling reference.
