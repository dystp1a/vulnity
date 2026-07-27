# Open Redirect

## Description
Occurs when an application redirects to a URL taken from user input
without validating it stays within the application's own domain, which
attackers can abuse for phishing by disguising a malicious link behind a
trusted domain.

## Remediation
- Validate any redirect target against an allowlist of known-safe paths or
  domains before issuing the redirect.
- Prefer relative paths (`/dashboard`) over accepting a full URL for
  internal redirects.
- If external redirects are a legitimate feature, show an interstitial
  warning page rather than redirecting silently.

## Verification
Submit a redirect parameter pointing to an external domain and confirm the
application now rejects it or redirects to a safe default instead.
