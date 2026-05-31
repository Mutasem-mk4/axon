## 2024-05-31 - [Insecure Output File Permissions]
**Vulnerability:** Output files were created using `os.Create` which grants `0o666` permissions, potentially exposing sensitive security reports to unauthorized local users.
**Learning:** Functions like `os.Create` should be avoided for sensitive files because they default to overly permissive permissions.
**Prevention:** Always use `os.OpenFile` with explicit `0600` permissions (e.g., `os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600`) when generating sensitive files.
