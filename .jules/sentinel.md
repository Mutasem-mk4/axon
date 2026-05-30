## 2025-02-18 - Enforce Strict File Permissions for Output Reports
**Vulnerability:** Output files (such as security reports) were being created with default permissions (`0666` before umask) using `os.Create`, allowing potential unauthorized read/write access.
**Learning:** `os.Create` uses overly permissive defaults for sensitive application output, creating a local privilege escalation and information disclosure risk.
**Prevention:** Use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)` with explicit restrictive permissions for all sensitive output files instead of `os.Create`.
