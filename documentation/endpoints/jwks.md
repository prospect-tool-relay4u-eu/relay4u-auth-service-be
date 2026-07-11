# `JwksController` — `/.well-known/jwks.json`

| Method | Path | Request | Response | Status |
|---|---|---|---|---|
| GET | `/.well-known/jwks.json` | – | JWKS document (`{ "keys": [...] }`) | 200 OK |

No request body, no auth required, no service/repository layer involved — this is effectively a static computed response.

## What it does

`JwksController.jwks()` builds an RSA JWK from `JwtUtil.getPublicKey()` (key id `auth-key-1`, algorithm `RS256`, use `sig`), wraps it in a `com.nimbusds.jose.jwk.JWKSet`, and returns `toJSONObject()`.

## Who consumes this

Any resource-server-style consumer of this auth service's JWTs — currently `eu-relay-4u-prospecting-be`, which points `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` at this endpoint (Spring Security handles fetching/caching the JWKS and matching tokens to keys by `kid` automatically). Adding a new consuming service only requires pointing it at this same URL — no coordination of shared secrets needed.

## Operational note

Because the public key is derived from the same in-memory RSA keypair described in [`architecture.md`](../architecture.md), a service restart without a persisted `JWT_PRIVATE_KEY` rotates this document's contents (new `n`/`e` values, same `kid`) — any tokens issued before the restart will fail signature validation afterwards.
