# Remote Code Execution (RCE)

## Description
RCE lets an attacker execute arbitrary code on the server, typically via
unsafe deserialization, `eval`/`Function` on user input, unsafe use of
`child_process` with unsanitized arguments, or an unrestricted file upload
combined with the ability to execute the uploaded file.

## Remediation
- Never pass user input into `eval()`, `new Function()`, `vm` module
  contexts, or template engine `render` calls that allow code execution.
- If shelling out is unavoidable, use `execFile`/`spawn` with an argument
  array (not string concatenation into a shell command), and validate/
  allowlist the inputs.
- Avoid deserializing untrusted data with formats/libraries that support
  arbitrary object/code reconstruction; prefer plain JSON.
- Restrict file uploads by type and size, store them outside the web root
  or with execute permissions stripped, and never serve uploaded files as
  executable.

## Verification
Confirm the previously working command-injection or code-execution payload
now fails safely (input rejected or properly escaped) rather than
executing.
