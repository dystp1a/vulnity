# Security Misconfiguration

## Description
Covers a broad class of issues from insecure default settings, missing
security headers, verbose error messages leaking stack traces, exposed
admin interfaces, or outdated TLS configuration.

## Remediation
- Set standard security headers: `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options` or a frame-ancestors
  CSP directive, and a Content-Security-Policy. Libraries like `helmet`
  for Express set sane defaults in one line.
- Disable verbose/stack-trace error responses in production; log details
  server-side and return a generic error to the client.
- Remove or auth-protect debug endpoints, admin panels, and directory
  listings before deploying.
- Keep TLS configuration current — disable old protocol versions and weak
  cipher suites.
- Ensure CORS is scoped to specific trusted origins rather than `*`,
  especially on endpoints that require credentials.

## Verification
Re-check response headers and error output after the fix; confirm no stack
traces or internal paths are leaked and CORS only allows intended origins.
