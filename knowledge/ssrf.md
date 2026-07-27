# Server-Side Request Forgery (SSRF)

## Description
SSRF occurs when an application fetches a URL supplied or influenced by the
user and an attacker can redirect that request to internal services, cloud
metadata endpoints, or otherwise unintended destinations.

## Remediation
- Maintain an allowlist of permitted destination hosts/schemes for any
  server-side fetch driven by user input; deny by default.
- Resolve and validate the destination IP is not in a private/loopback/
  link-local range before making the request, and re-check after any
  redirect (don't just validate the first URL).
- Block access to cloud metadata endpoints (e.g. 169.254.169.254)
  explicitly.
- Where possible, avoid letting users specify a full URL at all — accept
  an identifier and look up the destination server-side instead.

## Verification
Attempt to point the vulnerable parameter at an internal address or the
metadata endpoint and confirm the request is now blocked before it leaves
the server.
