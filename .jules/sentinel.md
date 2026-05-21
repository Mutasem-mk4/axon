## 2025-02-14 - Insecure File Permissions in os.Create

**Vulnerability:** Insecure file creation permissions via `os.Create` and `os.MkdirAll`. `os.Create` defaults to `0666` which can allow unauthorized users to read or write to the created files, depending on the umask. `os.MkdirAll` was creating directories with `0755` permissions, exposing contents to other local users.
**Learning:** `os.Create` does not explicitly constrain file permissions, making it risky for creating potentially sensitive output files. Standard library functions like `os.Create` and `os.MkdirAll` need explicit permission constraints (e.g. `0600` and `0700`) when dealing with security reports or logs to prevent local privilege escalation and unauthorized access.
**Prevention:** Avoid `os.Create`. Use `os.OpenFile` with explicit permissions (e.g., `os.O_CREATE|os.O_WRONLY|os.O_TRUNC` and `0600`) when creating files, and `os.MkdirAll` with `0700` when creating directories for potentially sensitive data.
