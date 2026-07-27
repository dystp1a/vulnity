# Path Traversal

## Description
Occurs when user input is used to build a filesystem path without
sufficient validation, letting an attacker use `../` sequences (or
equivalents) to read or write files outside the intended directory.

## Remediation
- Resolve the requested path with `path.resolve()`/`path.normalize()` and
  verify the result still starts with the intended base directory before
  using it.
- Avoid directly concatenating user input into file paths; where possible,
  map user-supplied identifiers to a fixed, server-controlled set of
  allowed files/paths rather than accepting a raw path.
- Run the process with the minimum filesystem permissions it needs.

## Verification
Submit a payload containing `../` sequences to the same parameter and
confirm the response no longer discloses files outside the intended
directory.
