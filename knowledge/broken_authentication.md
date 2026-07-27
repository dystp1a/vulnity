# Broken Authentication

## Description
Covers weaknesses in how an application verifies identity or manages
sessions: weak password handling, predictable or non-expiring tokens,
missing session invalidation, or JWTs that are trusted without proper
verification.

## Why it happens in Node.js / Express apps
Common causes: storing passwords with weak or no hashing (plain text, MD5,
unsalted SHA), signing JWTs with a weak/hardcoded secret, accepting the
`alg: none` JWT header, not invalidating sessions/tokens on logout or
password change, and missing expiration on tokens.

## Remediation
- Hash passwords with bcrypt, scrypt, or argon2 with a sufficient work
  factor; never roll your own hashing.
- Sign JWTs with a strong, environment-provided secret (or asymmetric keys),
  explicitly set and check the `alg`, and reject `none`.
- Set reasonable token/session expiration and implement server-side
  invalidation (e.g. a token blocklist or session store) for logout.
- Use `httpOnly`, `Secure`, and `SameSite` cookie attributes for session
  cookies.
- Rate-limit and lock out repeated failed login attempts.

## Verification
Confirm tokens expire as configured, that a logged-out session can no
longer access protected routes, and that a weak/forged token is rejected.
