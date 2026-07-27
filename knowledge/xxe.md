# XML External Entity (XXE)

## Description
XXE occurs when an XML parser processes external entity references in
attacker-supplied XML, allowing file disclosure, SSRF, or denial of service
through entity expansion ("billion laughs").

## Why it happens in Node.js / Express apps
Occurs when an app accepts XML input (SOAP endpoints, file uploads, SAML)
and parses it with a library that has external entity resolution enabled by
default.

## Remediation
- Disable DTD processing and external entity resolution in the XML parser
  configuration (e.g. `libxmljs`/`xml2js` equivalents — check the specific
  library's secure-parsing flags).
- Prefer JSON over XML for new APIs where possible.
- If XML is required, validate against a strict XML Schema and reject
  documents containing `<!DOCTYPE` or `<!ENTITY` declarations.

## Verification
Submit an XML payload referencing a local file or external URL via an
entity and confirm the parser no longer resolves it.
