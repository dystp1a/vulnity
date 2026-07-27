# Broken Access Control

## Description
Occurs when an application fails to enforce that a user can only act on
resources they're authorized for — commonly manifests as IDOR (Insecure
Direct Object Reference), where changing an ID in a request exposes another
user's data.

## Why it happens in Node.js / Express apps
Common causes: looking up a resource by ID from the request without
checking it belongs to the authenticated user, missing role checks on
admin routes, or relying only on hiding a URL/UI element (security through
obscurity) rather than server-side enforcement.

## Remediation
- On every route that accesses a resource by ID, verify server-side that
  the authenticated user owns or is authorized for that specific resource,
  not just that they're logged in.
- Centralize authorization checks in middleware rather than duplicating ad
  hoc checks per route.
- Default to deny — require an explicit authorization check rather than
  assuming access unless denied.
- Use non-sequential, non-guessable identifiers (UUIDs) where feasible to
  raise the bar for enumeration, as defense-in-depth only (not a substitute
  for the access check itself).

## Verification
As User A, attempt to access/modify a resource belonging to User B by ID
and confirm the request is now rejected with 403/404 rather than succeeding.
