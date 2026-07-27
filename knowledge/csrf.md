# Cross-Site Request Forgery (CSRF)

## Description
CSRF tricks an authenticated user's browser into submitting a request to
your application without their intent, exploiting the fact that cookies are
sent automatically with same-site or cross-site requests depending on
cookie attributes.

## Remediation
- Set the session cookie's `SameSite` attribute to `Lax` or `Strict` as a
  primary defense.
- For state-changing requests (POST/PUT/DELETE), require a CSRF token tied
  to the user's session and validate it server-side, or use a
  double-submit cookie pattern.
- Avoid relying on the `Referer`/`Origin` header alone as the only check,
  but it can be used as an additional signal.
- For pure JSON APIs consumed only by your own frontend via `fetch`/XHR
  with custom headers, confirm CORS is locked down — custom headers can't
  be set by a simple cross-site form submission, which itself mitigates
  classic CSRF for those endpoints.

## Verification
Confirm a forged cross-site request (without the token, or with SameSite
cookies blocked) is now rejected.
