# Security Policy

## Supported versions

The latest released version on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
private vulnerability reporting: repository **Security** tab → *Report a
vulnerability*. Reports stay private until a fix is published.

Include, when possible: affected version, a minimal reproduction, and the
observed impact. You should receive an acknowledgement within 7 days.

## Scope notes

The tool runs fully offline in read-only mode over evidence corpora supplied
by the operator, and treats the source tree as immutable. Reports of interest
include path-traversal or symlink escapes during attachment extraction,
directory traversal in output paths, unsafe handling of untrusted MIME
structures, or command/argument injection in the optional `openssl` and OCR
integrations.
