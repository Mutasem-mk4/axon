## 2024-05-28 - Insecure File Permissions for Reports and Logs
**Vulnerability:** Output files and logs were created with overly permissive file modes (e.g., 0666 via `os.Create` and 0644/0755 in logging), which could allow local privilege escalation and unauthorized read access to sensitive security reports and application logs.
**Learning:** `os.Create` defaults to 0666. Explicitly using `os.OpenFile` is required to ensure restrictive permissions are applied to sensitive files.
**Prevention:** Always use `os.OpenFile` with `0o600` for sensitive files and `os.MkdirAll` with `0o700` for their directories instead of `os.Create` or relying on default permissions.
