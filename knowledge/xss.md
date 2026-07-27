# Cross-Site Scripting (XSS)

## Description
XSS occurs when untrusted input is rendered into an HTML, JavaScript, or DOM
context without proper encoding, letting an attacker run script in another
user's browser session. Reflected, stored, and DOM-based XSS differ in where
the untrusted data originates and how it reaches the sink.

## Why it happens in Node.js / Express apps
Common causes: using `res.send()` or template engines with output-escaping
disabled, injecting user input into `innerHTML` on the client, or building
HTML strings manually instead of using the templating engine's default
auto-escaping.

## Remediation
- Use your templating engine's default auto-escaping (EJS `<%= %>`, Pug
  interpolation, Handlebars `{{ }}`) rather than the "unescaped" variants
  (`<%- %>`, `{{{ }}}`) unless the content is verified safe HTML.
- On the client, prefer `textContent` over `innerHTML` when inserting
  user-controlled strings.
- Set a Content-Security-Policy header restricting script sources as
  defense-in-depth.
- Set `X-Content-Type-Options: nosniff` and correct `Content-Type` headers on
  API responses so browsers don't misinterpret JSON/text as HTML.
- Sanitize any HTML you must accept from users with a maintained library
  (e.g. DOMPurify) rather than a custom regex-based filter.

## Verification
Confirm the previously reflected/stored payload is now rendered as inert
text (escaped entities) rather than executed.
