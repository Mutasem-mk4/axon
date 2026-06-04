## 2024-05-15 - Strict File Permissions for Output Reports
**Vulnerability:** Output files were created using `os.Create`, which defaults to 0666 permissions, potentially exposing sensitive security reports to other users on the same system.
**Learning:** Default file creation functions like `os.Create` do not apply restrictive permissions, which is dangerous when writing files that contain sensitive vulnerability data.
**Prevention:** Always use `os.OpenFile` with explicit strict permissions (e.g., `0o600`) and flags (`os.O_CREATE|os.O_WRONLY|os.O_TRUNC`) when creating or overwriting sensitive files.
